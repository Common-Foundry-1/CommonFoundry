//! Additive production-geometry WHIR candidate.
//!
//! This module defines and measures the exact n19/n31 role geometry and a
//! versioned n33 batched-model proposal without widening the legacy V2 adapter.
//! It also derives production work from verifier-visible commitments so the
//! final table need not be re-hashed inside a separate BLAKE3 STARK. It is
//! deliberately not a block-proof type: even the batched model's
//! dictionary-free floor exceeds the whole-frame shared argument budget and
//! therefore fails closed before activation.

use blake3::Hasher as Blake3Hasher;
use thiserror::Error;

use super::{
    Challenger, EF, EXPLICIT_WHIR_FOLDING, EXPLICIT_WHIR_POW_BITS, EXPLICIT_WHIR_SECURITY_BITS,
    EXPLICIT_WHIR_STARTING_LOG_INV_RATE, F, build_whir_config_bounded,
    native_codec::{self, NativeProofCodecError, NativeProofCodecProfile, NativeProofGeometry},
    structured_whir_suite_parameter_digest,
};
use crate::{
    BlockChallenge, ForgeMatrixV2Descriptor, MAX_MODEL_PCS_WEIGHT_BANKS, ModelPcsIdentity,
    ModelPcsRole, PRODUCTION_V2_BANKS, PRODUCTION_V2_BATCH, PRODUCTION_V2_DIMENSION,
    PRODUCTION_V2_LAYERS, PRODUCTION_V2_LAYERS_PER_BANK,
};

pub const PRODUCTION_WHIR_CANDIDATE_VERSION: u32 = 1;
pub const PRODUCTION_PROOF_BINDING_VERSION: u32 = 1;
pub const PRODUCTION_WHIR_BASE_VARIABLES: usize = 19;
pub const PRODUCTION_WHIR_WEIGHT_VARIABLES: usize = 31;
pub const PRODUCTION_BATCHED_MODEL_VARIABLES: usize = 33;
pub const PRODUCTION_BATCHED_MODEL_SLOT_VARIABLES: usize = PRODUCTION_WHIR_WEIGHT_VARIABLES;
pub const PRODUCTION_BATCHED_MODEL_SLOTS: usize = 1 + PRODUCTION_V2_BANKS as usize;
pub const PRODUCTION_FINAL_ACTIVATION_ELEMENTS: usize =
    PRODUCTION_V2_BATCH as usize * PRODUCTION_V2_DIMENSION as usize;
pub const PRODUCTION_WHIR_ABSOLUTE_NATIVE_BYTES: usize =
    match crate::wire::MAX_PROOF_BYTES.checked_sub(crate::wire::WIRE_HEADER_BYTES) {
        Some(bytes) => bytes,
        None => panic!("proof frame is smaller than its wire header"),
    };
pub const PRODUCTION_BATCHED_WHIR_MODEL_BYTES: usize =
    crate::structured_proof::STRUCTURED_BATCHED_PRODUCTION_MODEL_NATIVE_BYTES;

pub(super) const PRODUCTION_WHIR_NATIVE_MAGIC: &[u8; 8] = b"CMFDPWB1";
pub(super) const PRODUCTION_WHIR_NATIVE_CODEC_VERSION: u32 = 1;
pub(super) const PRODUCTION_WHIR_NATIVE_PROTOCOL_VERSION: u32 = 1;
pub(super) const PRODUCTION_BATCHED_WHIR_NATIVE_MAGIC: &[u8; 8] = b"CMFDPBJ1";
pub(super) const PRODUCTION_BATCHED_WHIR_NATIVE_CODEC_VERSION: u32 = 1;
pub(super) const PRODUCTION_BATCHED_WHIR_NATIVE_PROTOCOL_VERSION: u32 = 1;

const PRODUCTION_MODEL_VERSION: u32 = 2;
const CANDIDATE_SUITE_DOMAIN: &str = "CMFD/FORGEMATRIX/WHIR-PRODUCTION-CANDIDATE/V1";
const PROOF_BINDING_SUITE_DOMAIN: &str = "CMFD/FORGEMATRIX/PRODUCTION-PROOF-SUITE/V1";
const BATCHED_MODEL_IDENTITY_DOMAIN: &str = "CMFD/FORGEMATRIX/PRODUCTION-BATCHED-MODEL/V1";
const PROOF_COMMITMENT_ROOT_DOMAIN: &str = "CMFD/FORGEMATRIX/PRODUCTION-PROOF-COMMITMENT/V1";
const COMMITMENT_WORK_DOMAIN: &str = "CMFD/FORGEMATRIX/PRODUCTION-COMMITMENT-WORK/V1";
const COMMITMENT_PUBLIC_BINDING_DOMAIN: &str = "CMFD/FORGEMATRIX/PRODUCTION-COMMITMENT-PUBLIC/V1";
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

pub struct ProductionBatchedModelWhirConfigV1 {
    trusted_model_digest: [u8; 32],
    expected_commitment: [u8; 32],
    suite_digest: [u8; 32],
    inner: p3_whir::parameters::WhirConfig<EF, F, Challenger>,
}

impl std::fmt::Debug for ProductionBatchedModelWhirConfigV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionBatchedModelWhirConfigV1")
            .field("trusted_model_digest", &self.trusted_model_digest)
            .field("expected_commitment", &self.expected_commitment)
            .field("suite_digest", &self.suite_digest)
            .field("num_variables", &self.inner.num_variables)
            .finish()
    }
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
    pub available_native_bytes: usize,
    pub conservative_payload_fit: bool,
}

/// Trusted identity for one batched commitment to the ordered base-input and
/// three weight-bank polynomials.
///
/// The joint commitment must come from the model ceremony, not from a block or
/// miner. This descriptor binds it to the existing byte-authenticated model,
/// ordered role commitments, exact production geometry, and proof suite. It
/// does not itself prove that the ceremony formed the joint polynomial
/// correctly; that ceremony receipt remains a production activation gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionBatchedModelIdentityV1 {
    model_identity_digest: [u8; 32],
    model_byte_root: [u8; 32],
    source_pcs_suite_digest: [u8; 32],
    ordered_role_commitment_root: [u8; 32],
    joint_fixed_model_commitment: [u8; 32],
    proof_suite_digest: [u8; 32],
}

impl ProductionBatchedModelIdentityV1 {
    /// Research-only constructor. Activation must replace this with a verified
    /// model-ceremony receipt that proves the joint source layout.
    #[allow(dead_code)]
    pub(crate) fn from_unverified_ceremony_root(
        model: &ModelPcsIdentity,
        joint_fixed_model_commitment: [u8; 32],
    ) -> Result<Self, ProductionWhirCandidateError> {
        validate_production_model(model)?;
        if joint_fixed_model_commitment == [0; 32] {
            return Err(ProductionWhirCandidateError::UncommittedBatchedModel);
        }
        Ok(Self {
            model_identity_digest: model
                .digest()
                .map_err(|_| ProductionWhirCandidateError::InvalidModel)?,
            model_byte_root: model.model_byte_root,
            source_pcs_suite_digest: model.pcs_suite_parameter_digest,
            ordered_role_commitment_root: model
                .commitment_root()
                .map_err(|_| ProductionWhirCandidateError::InvalidModel)?,
            joint_fixed_model_commitment,
            proof_suite_digest: production_proof_binding_suite_digest_v1(),
        })
    }

    pub const fn joint_fixed_model_commitment(&self) -> [u8; 32] {
        self.joint_fixed_model_commitment
    }

    pub const fn proof_suite_digest(&self) -> [u8; 32] {
        self.proof_suite_digest
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Blake3Hasher::new_derive_key(BATCHED_MODEL_IDENTITY_DOMAIN);
        hasher.update(&PRODUCTION_PROOF_BINDING_VERSION.to_le_bytes());
        hasher.update(&self.proof_suite_digest);
        hasher.update(&self.model_identity_digest);
        hasher.update(&self.model_byte_root);
        hasher.update(&self.source_pcs_suite_digest);
        hasher.update(&self.ordered_role_commitment_root);
        hasher.update(&self.joint_fixed_model_commitment);
        *hasher.finalize().as_bytes()
    }
}

/// Opaque evidence that the production algebraic and PCS verifier accepted one
/// exact semantic trace layout and its terminal output alias.
///
/// There is intentionally no callable production constructor yet. The future
/// integrated verifier must validate the fixed table order, variables,
/// canonical padding, terminal-table identity, and every opening before it can
/// mint this capability. This keeps raw miner-supplied roots out of the work
/// binding API while that verifier bridge remains an activation gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedProductionTraceV1 {
    trusted_model_digest: [u8; 32],
    challenge_digest: [u8; 32],
    trace_commitment_root: [u8; 32],
    trace_layout_digest: [u8; 32],
    canonical_padding_digest: [u8; 32],
    trace_table_count: u32,
    terminal_table_index: u32,
    final_output_commitment: [u8; 32],
}

impl VerifiedProductionTraceV1 {
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    fn from_verified_parts(
        trusted_model_digest: [u8; 32],
        challenge_digest: [u8; 32],
        trace_commitment_root: [u8; 32],
        trace_layout_digest: [u8; 32],
        canonical_padding_digest: [u8; 32],
        trace_table_count: u32,
        terminal_table_index: u32,
        final_output_commitment: [u8; 32],
    ) -> Result<Self, ProductionWhirCandidateError> {
        if trace_commitment_root == [0; 32] {
            return Err(ProductionWhirCandidateError::UncommittedTrace);
        }
        if final_output_commitment == [0; 32] {
            return Err(ProductionWhirCandidateError::UncommittedFinalOutput);
        }
        if trace_layout_digest == [0; 32]
            || canonical_padding_digest == [0; 32]
            || trace_table_count == 0
            || trace_table_count as usize
                > crate::structured_proof::STRUCTURED_PRODUCTION_SPLIT_V3_MAX_TRACE_TABLES
            || terminal_table_index >= trace_table_count
        {
            return Err(ProductionWhirCandidateError::InvalidTraceIdentity);
        }
        Ok(Self {
            trusted_model_digest,
            challenge_digest,
            trace_commitment_root,
            trace_layout_digest,
            canonical_padding_digest,
            trace_table_count,
            terminal_table_index,
            final_output_commitment,
        })
    }
}

/// Verifier-derived commitment to every proof-specific polynomial root needed
/// by the production candidate. This value is never trusted from the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionProofCommitmentRootV1([u8; 32]);

impl ProductionProofCommitmentRootV1 {
    #[allow(dead_code)]
    pub(crate) fn derive(
        trusted_model: &ProductionBatchedModelIdentityV1,
        verified_trace: &VerifiedProductionTraceV1,
    ) -> Result<Self, ProductionWhirCandidateError> {
        if verified_trace.trusted_model_digest != trusted_model.digest() {
            return Err(ProductionWhirCandidateError::VerifiedTraceContextMismatch);
        }
        let mut hasher = Blake3Hasher::new_derive_key(PROOF_COMMITMENT_ROOT_DOMAIN);
        hasher.update(&PRODUCTION_PROOF_BINDING_VERSION.to_le_bytes());
        hasher.update(&trusted_model.proof_suite_digest());
        hasher.update(&trusted_model.digest());
        hasher.update(&verified_trace.challenge_digest);
        hasher.update(&verified_trace.trace_layout_digest);
        hasher.update(&verified_trace.trace_table_count.to_le_bytes());
        hasher.update(&verified_trace.terminal_table_index.to_le_bytes());
        hasher.update(&verified_trace.canonical_padding_digest);
        hasher.update(&verified_trace.trace_commitment_root);
        hasher.update(&verified_trace.final_output_commitment);
        hasher.update(&(PRODUCTION_FINAL_ACTIVATION_ELEMENTS as u64).to_le_bytes());
        Ok(Self(*hasher.finalize().as_bytes()))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Untrusted commitment-derived claims carried by a future production proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionCommitmentClaimsV1 {
    pub proof_commitment_root: [u8; 32],
    pub work_digest: [u8; 32],
    pub public_binding: [u8; 32],
}

/// Canonical nonce challenge and target recomputed from caller-owned block
/// data instead of accepted as two independent proof fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionCommitmentChallengeV1 {
    challenge_digest: [u8; 32],
    work_target: [u8; 32],
}

impl ProductionCommitmentChallengeV1 {
    #[allow(dead_code)]
    pub(crate) fn from_block(
        descriptor: &ForgeMatrixV2Descriptor,
        trusted_model: &ProductionBatchedModelIdentityV1,
        block: &BlockChallenge,
        nonce: u64,
    ) -> Result<Self, ProductionWhirCandidateError> {
        let production_descriptor_matches = descriptor.network_id != [0; 32]
            && descriptor.algorithm_version == crate::FORGEMATRIX_V2_ALGORITHM_VERSION
            && descriptor.proof_version == crate::FORGEMATRIX_V2_PROOF_VERSION
            && descriptor.banks == PRODUCTION_V2_BANKS
            && descriptor.layers_per_bank == PRODUCTION_V2_LAYERS_PER_BANK
            && descriptor.model.model_version == PRODUCTION_MODEL_VERSION
            && descriptor.model.batch == PRODUCTION_V2_BATCH
            && descriptor.model.dimension == PRODUCTION_V2_DIMENSION
            && descriptor.model.layers == PRODUCTION_V2_LAYERS
            && descriptor.model.raw_blake3_root == trusted_model.model_byte_root
            && descriptor.model.pcs_parameter_digest == trusted_model.source_pcs_suite_digest
            && descriptor.model.pcs_commitment_root == trusted_model.ordered_role_commitment_root
            && descriptor.model.digest().is_ok();
        if !production_descriptor_matches {
            return Err(ProductionWhirCandidateError::InvalidProductionDescriptor);
        }
        Ok(Self {
            challenge_digest: crate::forgematrix_v2::challenge_digest(descriptor, block, nonce)
                .map_err(|_| ProductionWhirCandidateError::InvalidChallenge)?,
            work_target: block.target,
        })
    }

    #[cfg(test)]
    const fn from_test_parts(challenge_digest: [u8; 32], work_target: [u8; 32]) -> Self {
        Self {
            challenge_digest,
            work_target,
        }
    }

    pub const fn challenge_digest(&self) -> [u8; 32] {
        self.challenge_digest
    }

    pub const fn work_target(&self) -> [u8; 32] {
        self.work_target
    }
}

/// Work and Fiat-Shamir bindings derived from authenticated commitments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionCommitmentWorkBindingV1 {
    proof_commitment_root: ProductionProofCommitmentRootV1,
    work_digest: [u8; 32],
    public_binding: [u8; 32],
}

impl ProductionCommitmentWorkBindingV1 {
    #[allow(dead_code)]
    pub(crate) fn derive(
        challenge: ProductionCommitmentChallengeV1,
        trusted_model: &ProductionBatchedModelIdentityV1,
        verified_trace: &VerifiedProductionTraceV1,
    ) -> Result<Self, ProductionWhirCandidateError> {
        if verified_trace.challenge_digest != challenge.challenge_digest() {
            return Err(ProductionWhirCandidateError::VerifiedTraceContextMismatch);
        }
        let proof_commitment_root =
            ProductionProofCommitmentRootV1::derive(trusted_model, verified_trace)?;
        let mut work = Blake3Hasher::new_derive_key(COMMITMENT_WORK_DOMAIN);
        work.update(&PRODUCTION_PROOF_BINDING_VERSION.to_le_bytes());
        work.update(&challenge.challenge_digest());
        work.update(proof_commitment_root.as_bytes());
        let work_digest = *work.finalize().as_bytes();

        let mut binding = Blake3Hasher::new_derive_key(COMMITMENT_PUBLIC_BINDING_DOMAIN);
        binding.update(&PRODUCTION_PROOF_BINDING_VERSION.to_le_bytes());
        binding.update(&trusted_model.proof_suite_digest());
        binding.update(&challenge.challenge_digest());
        binding.update(proof_commitment_root.as_bytes());
        binding.update(&work_digest);
        binding.update(&challenge.work_target());
        let public_binding = *binding.finalize().as_bytes();
        Ok(Self {
            proof_commitment_root,
            work_digest,
            public_binding,
        })
    }

    pub const fn proof_commitment_root(&self) -> ProductionProofCommitmentRootV1 {
        self.proof_commitment_root
    }

    pub const fn work_digest(&self) -> [u8; 32] {
        self.work_digest
    }

    pub const fn public_binding(&self) -> [u8; 32] {
        self.public_binding
    }

    pub const fn claims(&self) -> ProductionCommitmentClaimsV1 {
        ProductionCommitmentClaimsV1 {
            proof_commitment_root: *self.proof_commitment_root.as_bytes(),
            work_digest: self.work_digest,
            public_binding: self.public_binding,
        }
    }
}

/// Re-derives every commitment claim from verifier-authenticated inputs.
///
/// The opaque trace capability can only be minted by the future integrated PCS
/// and algebraic verifier after it accepts the exact semantic layout and
/// terminal alias. Callers must never accept these claims independently of
/// that proof result.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub(crate) fn verify_production_commitment_claims_v1(
    challenge: ProductionCommitmentChallengeV1,
    trusted_model: &ProductionBatchedModelIdentityV1,
    verified_trace: &VerifiedProductionTraceV1,
    claimed: &ProductionCommitmentClaimsV1,
) -> Result<(), ProductionWhirCandidateError> {
    let expected =
        ProductionCommitmentWorkBindingV1::derive(challenge, trusted_model, verified_trace)?;
    if claimed.proof_commitment_root != *expected.proof_commitment_root().as_bytes() {
        return Err(ProductionWhirCandidateError::ProofCommitmentMismatch);
    }
    if claimed.work_digest != expected.work_digest() {
        return Err(ProductionWhirCandidateError::WorkDigestMismatch);
    }
    if claimed.public_binding != expected.public_binding() {
        return Err(ProductionWhirCandidateError::PublicBindingMismatch);
    }
    if claimed.work_digest > challenge.work_target() {
        return Err(ProductionWhirCandidateError::HighHash);
    }
    Ok(())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProductionWhirCandidateError {
    #[error("model identity is not the exact ForgeMatrix-v2 production geometry")]
    InvalidModel,
    #[error("model role is not one of the exact production base/weight roles")]
    InvalidRole,
    #[error("model role offset is outside its exact production table")]
    InvalidRoleOffset,
    #[error("model role opening point has the wrong variable count")]
    InvalidOpeningPoint,
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
    #[error("batched fixed-model identity has no trusted joint commitment")]
    UncommittedBatchedModel,
    #[error("production proof has no authenticated trace commitment")]
    UncommittedTrace,
    #[error("production proof has no authenticated final-output commitment")]
    UncommittedFinalOutput,
    #[error("production trace layout, padding, or terminal alias is not verifier-authenticated")]
    InvalidTraceIdentity,
    #[error("verified production trace belongs to a different model or block challenge")]
    VerifiedTraceContextMismatch,
    #[error("production proof commitment root mismatch")]
    ProofCommitmentMismatch,
    #[error("production commitment-derived work digest mismatch")]
    WorkDigestMismatch,
    #[error("production commitment-derived public binding mismatch")]
    PublicBindingMismatch,
    #[error("production commitment-derived work digest does not meet the target")]
    HighHash,
    #[error("production challenge could not be recomputed from the block and nonce")]
    InvalidChallenge,
    #[error("block descriptor does not match the trusted production model and geometry")]
    InvalidProductionDescriptor,
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
        Ok(wire_shape(geometry, PRODUCTION_WHIR_ABSOLUTE_NATIVE_BYTES))
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

impl ProductionBatchedModelWhirConfigV1 {
    pub fn for_trusted_model(
        trusted_model: &ProductionBatchedModelIdentityV1,
    ) -> Result<Self, ProductionWhirCandidateError> {
        let inner = build_whir_config_bounded(
            PRODUCTION_BATCHED_MODEL_VARIABLES,
            PRODUCTION_BATCHED_MODEL_VARIABLES,
        )
        .map_err(|_| ProductionWhirCandidateError::Configuration)?;
        Ok(Self {
            trusted_model_digest: trusted_model.digest(),
            expected_commitment: trusted_model.joint_fixed_model_commitment(),
            suite_digest: production_proof_binding_suite_digest_v1(),
            inner,
        })
    }

    pub const fn num_variables(&self) -> usize {
        PRODUCTION_BATCHED_MODEL_VARIABLES
    }

    pub const fn trusted_model_digest(&self) -> [u8; 32] {
        self.trusted_model_digest
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
            batched_candidate_codec_profile(usize::MAX),
        )
        .map_err(|_| ProductionWhirCandidateError::Configuration)?;
        Ok(wire_shape(geometry, PRODUCTION_BATCHED_WHIR_MODEL_BYTES))
    }

    pub fn validate_native_proof_encoding(
        &self,
        encoded: &[u8],
    ) -> Result<(), ProductionWhirCandidateError> {
        let shape = self.wire_shape()?;
        if shape.dictionary_free_floor_bytes > PRODUCTION_BATCHED_WHIR_MODEL_BYTES {
            return Err(ProductionWhirCandidateError::NetworkBudgetExceeded {
                minimum: shape.dictionary_free_floor_bytes,
                available: PRODUCTION_BATCHED_WHIR_MODEL_BYTES,
            });
        }
        if encoded.len() > PRODUCTION_BATCHED_WHIR_MODEL_BYTES {
            return Err(ProductionWhirCandidateError::NativeProofTooLarge);
        }
        let profile = batched_candidate_codec_profile(PRODUCTION_BATCHED_WHIR_MODEL_BYTES);
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

/// Digest of the complete commitment-derived production binding proposal.
///
/// This is separate from the per-role WHIR suite so adding the batched proof
/// architecture cannot silently reinterpret already-generated artifacts.
pub fn production_proof_binding_suite_digest_v1() -> [u8; 32] {
    let mut hasher = Blake3Hasher::new_derive_key(PROOF_BINDING_SUITE_DOMAIN);
    update_u64(
        &mut hasher,
        b"binding-version",
        PRODUCTION_PROOF_BINDING_VERSION as u64,
    );
    update_u64(
        &mut hasher,
        b"forgematrix-algorithm-version",
        crate::FORGEMATRIX_V2_ALGORITHM_VERSION as u64,
    );
    update_u64(
        &mut hasher,
        b"forgematrix-proof-version",
        crate::FORGEMATRIX_V2_PROOF_VERSION as u64,
    );
    update_descriptor(
        &mut hasher,
        b"whir-candidate-suite",
        &production_whir_suite_parameter_digest_v1(),
    );
    update_descriptor(
        &mut hasher,
        b"fixed-model-layout",
        b"four-equal-n31-slots-concatenated-into-one-n33-polynomial",
    );
    update_u64(
        &mut hasher,
        b"fixed-model-joint-variables",
        PRODUCTION_BATCHED_MODEL_VARIABLES as u64,
    );
    update_u64(
        &mut hasher,
        b"fixed-model-slot-variables",
        PRODUCTION_BATCHED_MODEL_SLOT_VARIABLES as u64,
    );
    update_u64(
        &mut hasher,
        b"fixed-model-slot-count",
        PRODUCTION_BATCHED_MODEL_SLOTS as u64,
    );
    update_u64(
        &mut hasher,
        b"maximum-batched-model-native-bytes",
        PRODUCTION_BATCHED_WHIR_MODEL_BYTES as u64,
    );
    update_descriptor(
        &mut hasher,
        b"fixed-model-slot-order",
        b"base-input,weight-bank-0,weight-bank-1,weight-bank-2",
    );
    update_descriptor(
        &mut hasher,
        b"fixed-model-linear-index",
        b"slot-index-times-2^31-plus-role-local-index",
    );
    update_descriptor(
        &mut hasher,
        b"fixed-model-base-padding",
        b"goldilocks-zero-for-local-indices-2^19-through-exclusive-2^31",
    );
    update_descriptor(
        &mut hasher,
        b"fixed-model-variable-order",
        b"suffix-low-31-role-local-bits-high-2-slot-selector-bits",
    );
    update_descriptor(
        &mut hasher,
        b"fixed-model-opening-lift",
        b"base=[selector-be2(0),zero^12,r19];weight-i=[selector-be2(i+1),r31]",
    );
    update_descriptor(
        &mut hasher,
        b"batched-native-codec",
        NATIVE_CODEC_DESCRIPTION,
    );
    update_descriptor(
        &mut hasher,
        b"batched-native-magic",
        PRODUCTION_BATCHED_WHIR_NATIVE_MAGIC,
    );
    update_u64(
        &mut hasher,
        b"batched-native-codec-version",
        PRODUCTION_BATCHED_WHIR_NATIVE_CODEC_VERSION as u64,
    );
    update_u64(
        &mut hasher,
        b"batched-native-protocol-version",
        PRODUCTION_BATCHED_WHIR_NATIVE_PROTOCOL_VERSION as u64,
    );
    update_descriptor(
        &mut hasher,
        b"trace-layout",
        b"activation-gated-exact-semantic-layout-digest-and-table-count",
    );
    update_u64(
        &mut hasher,
        b"maximum-trace-tables",
        crate::structured_proof::STRUCTURED_PRODUCTION_SPLIT_V3_MAX_TRACE_TABLES as u64,
    );
    update_descriptor(
        &mut hasher,
        b"trace-table-count-encoding",
        b"u32-little-endian-nonzero-at-most-maximum-trace-tables",
    );
    update_descriptor(
        &mut hasher,
        b"terminal-table-index-encoding",
        b"u32-little-endian-strictly-less-than-trace-table-count",
    );
    update_descriptor(
        &mut hasher,
        b"verified-trace-capability",
        b"sealed-after-algebraic-pcs-layout-padding-and-terminal-alias-checks;binds-trusted-model-digest-and-block-challenge-digest",
    );
    update_descriptor(
        &mut hasher,
        b"commitment-randomness",
        b"none-deterministic-non-hiding-canonical-padding",
    );
    update_u64(
        &mut hasher,
        b"final-output-elements",
        PRODUCTION_FINAL_ACTIVATION_ELEMENTS as u64,
    );
    update_descriptor(
        &mut hasher,
        b"final-output-binding",
        b"sealed-terminal-table-alias-equals-terminal-wiring-commitment",
    );
    update_descriptor(
        &mut hasher,
        b"final-output-hash-argument",
        b"absent-work-binds-authenticated-canonical-final-trace-commitment",
    );
    update_descriptor(
        &mut hasher,
        b"work-relation",
        b"blake3(challenge-digest,verifier-derived-proof-commitment-root)",
    );
    update_descriptor(
        &mut hasher,
        b"work-target-order",
        b"unsigned-big-endian-256-bit-work-digest-less-than-or-equal-target",
    );
    update_descriptor(
        &mut hasher,
        b"batched-model-domain",
        BATCHED_MODEL_IDENTITY_DOMAIN.as_bytes(),
    );
    update_descriptor(
        &mut hasher,
        b"proof-commitment-domain",
        PROOF_COMMITMENT_ROOT_DOMAIN.as_bytes(),
    );
    update_descriptor(
        &mut hasher,
        b"work-domain",
        COMMITMENT_WORK_DOMAIN.as_bytes(),
    );
    update_descriptor(
        &mut hasher,
        b"public-binding-domain",
        COMMITMENT_PUBLIC_BINDING_DOMAIN.as_bytes(),
    );
    *hasher.finalize().as_bytes()
}

/// Maps an existing fixed-model role element into the exact n33 batched source.
/// The unused tail of slot zero is canonically Goldilocks zero.
pub fn production_batched_model_source_index_v1(
    role: ProductionWhirRoleV1,
    role_offset: u64,
) -> Result<u64, ProductionWhirCandidateError> {
    let (slot, role_elements) = match role {
        ProductionWhirRoleV1::BaseInput => (0_u64, 1_u64 << PRODUCTION_WHIR_BASE_VARIABLES),
        ProductionWhirRoleV1::WeightBank { index } if index < PRODUCTION_V2_BANKS as u8 => (
            u64::from(index) + 1,
            1_u64 << PRODUCTION_WHIR_WEIGHT_VARIABLES,
        ),
        ProductionWhirRoleV1::WeightBank { .. } => {
            return Err(ProductionWhirCandidateError::InvalidRole);
        }
    };
    if role_offset >= role_elements {
        return Err(ProductionWhirCandidateError::InvalidRoleOffset);
    }
    slot.checked_shl(PRODUCTION_BATCHED_MODEL_SLOT_VARIABLES as u32)
        .and_then(|start| start.checked_add(role_offset))
        .ok_or(ProductionWhirCandidateError::Configuration)
}

/// Lifts a role-local multilinear opening into the exact n33 joint model.
pub fn production_batched_model_lift_point_v1(
    role: ProductionWhirRoleV1,
    role_point: &[crate::ExtensionElement],
) -> Result<Vec<crate::ExtensionElement>, ProductionWhirCandidateError> {
    if role_point.len() != role.num_variables() {
        return Err(ProductionWhirCandidateError::InvalidOpeningPoint);
    }
    let slot = match role {
        ProductionWhirRoleV1::BaseInput => 0_u8,
        ProductionWhirRoleV1::WeightBank { index } if index < PRODUCTION_V2_BANKS as u8 => {
            index + 1
        }
        ProductionWhirRoleV1::WeightBank { .. } => {
            return Err(ProductionWhirCandidateError::InvalidRole);
        }
    };
    let zero = crate::ExtensionElement { limbs: [0; 3] };
    let one = crate::ExtensionElement { limbs: [1, 0, 0] };
    let mut lifted = Vec::with_capacity(PRODUCTION_BATCHED_MODEL_VARIABLES);
    lifted.push(if slot & 0b10 == 0 { zero } else { one });
    lifted.push(if slot & 0b01 == 0 { zero } else { one });
    if role == ProductionWhirRoleV1::BaseInput {
        lifted.extend(std::iter::repeat_n(
            zero,
            PRODUCTION_BATCHED_MODEL_SLOT_VARIABLES - PRODUCTION_WHIR_BASE_VARIABLES,
        ));
    }
    lifted.extend_from_slice(role_point);
    debug_assert_eq!(lifted.len(), PRODUCTION_BATCHED_MODEL_VARIABLES);
    Ok(lifted)
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

pub(super) const fn batched_candidate_codec_profile(
    max_encoded_bytes: usize,
) -> NativeProofCodecProfile {
    NativeProofCodecProfile::new(
        PRODUCTION_BATCHED_WHIR_NATIVE_MAGIC,
        PRODUCTION_BATCHED_WHIR_NATIVE_CODEC_VERSION,
        PRODUCTION_BATCHED_WHIR_NATIVE_PROTOCOL_VERSION,
        PRODUCTION_BATCHED_MODEL_VARIABLES,
        max_encoded_bytes,
    )
}

fn wire_shape(geometry: NativeProofGeometry, available_bytes: usize) -> ProductionWhirWireShapeV1 {
    ProductionWhirWireShapeV1 {
        intermediate_rounds: geometry.intermediate_rounds,
        path_depths: geometry.path_depths,
        body_bytes: geometry.body_bytes,
        reference_count: geometry.reference_count,
        maximum_dictionary_nodes: geometry.maximum_dictionary_nodes,
        dictionary_free_floor_bytes: geometry.structural_floor_bytes,
        maximum_native_bytes: geometry.conservative_upper_bound_bytes,
        available_native_bytes: available_bytes,
        conservative_payload_fit: geometry.conservative_upper_bound_bytes <= available_bytes,
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
    use crate::ExtensionElement;

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

    fn production_descriptor(model: &ModelPcsIdentity) -> ForgeMatrixV2Descriptor {
        let dimension = u64::from(PRODUCTION_V2_DIMENSION);
        let base_input_bytes = u64::from(PRODUCTION_V2_BATCH) * dimension;
        let bytes_per_layer = dimension * dimension;
        ForgeMatrixV2Descriptor {
            network_id: [0x63; 32],
            algorithm_version: crate::FORGEMATRIX_V2_ALGORITHM_VERSION,
            proof_version: crate::FORGEMATRIX_V2_PROOF_VERSION,
            banks: PRODUCTION_V2_BANKS,
            layers_per_bank: PRODUCTION_V2_LAYERS_PER_BANK,
            model: crate::ModelBankManifest {
                model_version: PRODUCTION_MODEL_VERSION,
                dimension: PRODUCTION_V2_DIMENSION,
                batch: PRODUCTION_V2_BATCH,
                layers: PRODUCTION_V2_LAYERS,
                base_input_bytes,
                bytes_per_layer,
                payload_bytes: u64::from(PRODUCTION_V2_LAYERS) * bytes_per_layer + base_input_bytes,
                raw_blake3_root: model.model_byte_root,
                layer_roots_aggregate: [0x32; 32],
                pcs_parameter_digest: model.pcs_suite_parameter_digest,
                pcs_commitment_root: model.commitment_root().unwrap(),
            },
        }
    }

    fn verified_trace(
        trusted_model: &ProductionBatchedModelIdentityV1,
        challenge: ProductionCommitmentChallengeV1,
        trace_commitment_root: [u8; 32],
        final_output_commitment: [u8; 32],
    ) -> VerifiedProductionTraceV1 {
        VerifiedProductionTraceV1::from_verified_parts(
            trusted_model.digest(),
            challenge.challenge_digest(),
            trace_commitment_root,
            [0x63; 32],
            [0x64; 32],
            2,
            1,
            final_output_commitment,
        )
        .unwrap()
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
        assert_eq!(
            base_shape.available_native_bytes,
            PRODUCTION_WHIR_ABSOLUTE_NATIVE_BYTES
        );
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
            assert_eq!(
                shape.available_native_bytes,
                PRODUCTION_WHIR_ABSOLUTE_NATIVE_BYTES
            );
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

    #[test]
    fn commitment_challenge_is_recomputed_with_the_header_target() {
        let model = production_model();
        let trusted =
            ProductionBatchedModelIdentityV1::from_unverified_ceremony_root(&model, [0x61; 32])
                .unwrap();
        let descriptor = production_descriptor(&model);
        let block = BlockChallenge {
            network_id: descriptor.network_id,
            previous_block: [0x11; 32],
            transaction_root: [0x22; 32],
            height: 42,
            timestamp: 1_777_777_777,
            target: [0x7f; 32],
        };
        let challenge =
            ProductionCommitmentChallengeV1::from_block(&descriptor, &trusted, &block, 9).unwrap();
        assert_eq!(challenge.work_target(), block.target);
        assert_eq!(
            challenge.challenge_digest(),
            crate::forgematrix_v2::challenge_digest(&descriptor, &block, 9).unwrap()
        );

        let mut different_target = block;
        different_target.target[0] ^= 1;
        let different = ProductionCommitmentChallengeV1::from_block(
            &descriptor,
            &trusted,
            &different_target,
            9,
        )
        .unwrap();
        assert_ne!(challenge.challenge_digest(), different.challenge_digest());
        assert_ne!(challenge.work_target(), different.work_target());

        let mut wrong_network = block;
        wrong_network.network_id[0] ^= 1;
        assert_eq!(
            ProductionCommitmentChallengeV1::from_block(&descriptor, &trusted, &wrong_network, 9,),
            Err(ProductionWhirCandidateError::InvalidChallenge)
        );

        let tiny = crate::v2_test_reference().unwrap().descriptor();
        assert_eq!(
            ProductionCommitmentChallengeV1::from_block(&tiny, &trusted, &block, 9),
            Err(ProductionWhirCandidateError::InvalidProductionDescriptor)
        );
        let mut wrong_model = descriptor;
        wrong_model.model.pcs_commitment_root[0] ^= 1;
        assert_eq!(
            ProductionCommitmentChallengeV1::from_block(&wrong_model, &trusted, &block, 9),
            Err(ProductionWhirCandidateError::InvalidProductionDescriptor)
        );
    }

    #[test]
    fn batched_model_layout_has_four_exact_n31_slots() {
        assert_eq!(PRODUCTION_BATCHED_MODEL_VARIABLES, 33);
        assert_eq!(PRODUCTION_BATCHED_MODEL_SLOT_VARIABLES, 31);
        assert_eq!(PRODUCTION_BATCHED_MODEL_SLOTS, 4);
        assert_eq!(
            production_batched_model_source_index_v1(ProductionWhirRoleV1::BaseInput, 0),
            Ok(0)
        );
        assert_eq!(
            production_batched_model_source_index_v1(
                ProductionWhirRoleV1::BaseInput,
                (1_u64 << 19) - 1,
            ),
            Ok((1_u64 << 19) - 1)
        );
        assert_eq!(
            production_batched_model_source_index_v1(ProductionWhirRoleV1::BaseInput, 1_u64 << 19,),
            Err(ProductionWhirCandidateError::InvalidRoleOffset)
        );
        for index in 0..PRODUCTION_V2_BANKS as u8 {
            let slot_start = (u64::from(index) + 1) << 31;
            assert_eq!(
                production_batched_model_source_index_v1(
                    ProductionWhirRoleV1::WeightBank { index },
                    0,
                ),
                Ok(slot_start)
            );
            assert_eq!(
                production_batched_model_source_index_v1(
                    ProductionWhirRoleV1::WeightBank { index },
                    (1_u64 << 31) - 1,
                ),
                Ok(slot_start + (1_u64 << 31) - 1)
            );
            assert_eq!(
                production_batched_model_source_index_v1(
                    ProductionWhirRoleV1::WeightBank { index },
                    1_u64 << 31,
                ),
                Err(ProductionWhirCandidateError::InvalidRoleOffset)
            );
        }
        assert_eq!(
            production_batched_model_source_index_v1(
                ProductionWhirRoleV1::WeightBank { index: 3 },
                0,
            ),
            Err(ProductionWhirCandidateError::InvalidRole)
        );
    }

    #[test]
    fn batched_model_opening_lift_matches_the_linear_index_layout() {
        let boolean_point = |index: u64, variables: usize| {
            (0..variables)
                .map(|coordinate| ExtensionElement {
                    limbs: [(index >> (variables - coordinate - 1)) & 1, 0, 0],
                })
                .collect::<Vec<_>>()
        };
        let boolean_index = |point: &[ExtensionElement]| {
            point.iter().fold(0_u64, |index, coordinate| {
                assert_eq!(coordinate.limbs[1..], [0, 0]);
                assert!(coordinate.limbs[0] <= 1);
                (index << 1) | coordinate.limbs[0]
            })
        };

        for offset in [0, 1, (1_u64 << 19) - 1] {
            let role = ProductionWhirRoleV1::BaseInput;
            let point = boolean_point(offset, PRODUCTION_WHIR_BASE_VARIABLES);
            let lifted = production_batched_model_lift_point_v1(role, &point).unwrap();
            assert_eq!(lifted.len(), PRODUCTION_BATCHED_MODEL_VARIABLES);
            assert!(
                lifted[..14]
                    .iter()
                    .all(|coordinate| coordinate.limbs == [0; 3])
            );
            assert_eq!(
                boolean_index(&lifted),
                production_batched_model_source_index_v1(role, offset).unwrap()
            );
        }
        for index in 0..PRODUCTION_V2_BANKS as u8 {
            let role = ProductionWhirRoleV1::WeightBank { index };
            for offset in [0, 1, (1_u64 << 31) - 1] {
                let point = boolean_point(offset, PRODUCTION_WHIR_WEIGHT_VARIABLES);
                let lifted = production_batched_model_lift_point_v1(role, &point).unwrap();
                assert_eq!(lifted.len(), PRODUCTION_BATCHED_MODEL_VARIABLES);
                assert_eq!(
                    boolean_index(&lifted),
                    production_batched_model_source_index_v1(role, offset).unwrap()
                );
            }
        }
        assert_eq!(
            production_batched_model_lift_point_v1(
                ProductionWhirRoleV1::BaseInput,
                &boolean_point(0, PRODUCTION_WHIR_BASE_VARIABLES - 1),
            ),
            Err(ProductionWhirCandidateError::InvalidOpeningPoint)
        );
        assert_eq!(
            production_batched_model_lift_point_v1(
                ProductionWhirRoleV1::WeightBank { index: 3 },
                &boolean_point(0, PRODUCTION_WHIR_WEIGHT_VARIABLES),
            ),
            Err(ProductionWhirCandidateError::InvalidRole)
        );
    }

    #[test]
    fn batched_model_whir_geometry_is_measured_before_activation() {
        let model = production_model();
        let trusted =
            ProductionBatchedModelIdentityV1::from_unverified_ceremony_root(&model, [0x61; 32])
                .unwrap();
        let config = ProductionBatchedModelWhirConfigV1::for_trusted_model(&trusted).unwrap();
        assert_eq!(config.num_variables(), 33);
        assert_eq!(config.trusted_model_digest(), trusted.digest());
        assert_eq!(config.expected_commitment(), [0x61; 32]);
        assert_eq!(config.suite_digest(), trusted.proof_suite_digest());
        let shape = config.wire_shape().unwrap();
        assert_eq!(shape.intermediate_rounds, 13);
        assert_eq!(shape.path_depths, (19..=32).rev().collect::<Vec<_>>());
        assert_eq!(shape.body_bytes, 183_824);
        assert_eq!(shape.reference_count, 55_021);
        assert_eq!(shape.maximum_dictionary_nodes, 43_880);
        assert_eq!(shape.dictionary_free_floor_bytes, 293_906);
        assert_eq!(shape.maximum_native_bytes, 1_698_066);
        assert_eq!(
            shape.available_native_bytes,
            PRODUCTION_BATCHED_WHIR_MODEL_BYTES
        );
        assert!(!shape.conservative_payload_fit);
        assert_eq!(
            config.validate_native_proof_encoding(&[]),
            Err(ProductionWhirCandidateError::NetworkBudgetExceeded {
                minimum: shape.dictionary_free_floor_bytes,
                available: PRODUCTION_BATCHED_WHIR_MODEL_BYTES,
            })
        );
    }

    #[test]
    fn commitment_derived_work_binding_binds_the_sealed_candidate_identity() {
        let model = production_model();
        assert_eq!(
            ProductionBatchedModelIdentityV1::from_unverified_ceremony_root(&model, [0; 32]),
            Err(ProductionWhirCandidateError::UncommittedBatchedModel)
        );
        let trusted =
            ProductionBatchedModelIdentityV1::from_unverified_ceremony_root(&model, [0x61; 32])
                .unwrap();
        assert_ne!(
            trusted.proof_suite_digest(),
            production_whir_suite_parameter_digest_v1()
        );
        let challenge = ProductionCommitmentChallengeV1::from_test_parts([0x11; 32], [0x7f; 32]);
        assert_eq!(
            VerifiedProductionTraceV1::from_verified_parts(
                trusted.digest(),
                challenge.challenge_digest(),
                [0; 32],
                [0x63; 32],
                [0x64; 32],
                2,
                1,
                [0x71; 32],
            ),
            Err(ProductionWhirCandidateError::UncommittedTrace)
        );
        assert_eq!(
            VerifiedProductionTraceV1::from_verified_parts(
                trusted.digest(),
                challenge.challenge_digest(),
                [0x62; 32],
                [0x63; 32],
                [0x64; 32],
                2,
                1,
                [0; 32],
            ),
            Err(ProductionWhirCandidateError::UncommittedFinalOutput)
        );
        assert_eq!(
            VerifiedProductionTraceV1::from_verified_parts(
                trusted.digest(),
                challenge.challenge_digest(),
                [0x62; 32],
                [0; 32],
                [0x64; 32],
                2,
                1,
                [0x71; 32],
            ),
            Err(ProductionWhirCandidateError::InvalidTraceIdentity)
        );
        assert_eq!(
            VerifiedProductionTraceV1::from_verified_parts(
                trusted.digest(),
                challenge.challenge_digest(),
                [0x62; 32],
                [0x63; 32],
                [0x64; 32],
                2,
                2,
                [0x71; 32],
            ),
            Err(ProductionWhirCandidateError::InvalidTraceIdentity)
        );

        let trace = verified_trace(&trusted, challenge, [0x62; 32], [0x71; 32]);
        let binding =
            ProductionCommitmentWorkBindingV1::derive(challenge, &trusted, &trace).unwrap();
        let different_challenge =
            ProductionCommitmentChallengeV1::from_test_parts([0x12; 32], [0x7f; 32]);
        assert_eq!(
            ProductionCommitmentWorkBindingV1::derive(different_challenge, &trusted, &trace),
            Err(ProductionWhirCandidateError::VerifiedTraceContextMismatch)
        );
        let different_challenge_trace =
            verified_trace(&trusted, different_challenge, [0x62; 32], [0x71; 32]);
        let different_challenge_binding = ProductionCommitmentWorkBindingV1::derive(
            different_challenge,
            &trusted,
            &different_challenge_trace,
        )
        .unwrap();
        assert_ne!(
            binding.proof_commitment_root,
            different_challenge_binding.proof_commitment_root
        );
        assert_ne!(binding.work_digest, different_challenge_binding.work_digest);
        assert_ne!(
            binding.public_binding,
            different_challenge_binding.public_binding
        );

        let different_target = ProductionCommitmentWorkBindingV1::derive(
            ProductionCommitmentChallengeV1::from_test_parts([0x11; 32], [0x7e; 32]),
            &trusted,
            &trace,
        )
        .unwrap();
        assert_eq!(binding.work_digest, different_target.work_digest);
        assert_ne!(binding.public_binding, different_target.public_binding);

        let different_trace = ProductionCommitmentWorkBindingV1::derive(
            challenge,
            &trusted,
            &verified_trace(&trusted, challenge, [0x65; 32], [0x71; 32]),
        )
        .unwrap();
        assert_ne!(
            binding.proof_commitment_root,
            different_trace.proof_commitment_root
        );
        assert_ne!(binding.work_digest, different_trace.work_digest);

        for different_identity in [
            VerifiedProductionTraceV1::from_verified_parts(
                trusted.digest(),
                challenge.challenge_digest(),
                [0x62; 32],
                [0x66; 32],
                [0x64; 32],
                2,
                1,
                [0x71; 32],
            )
            .unwrap(),
            VerifiedProductionTraceV1::from_verified_parts(
                trusted.digest(),
                challenge.challenge_digest(),
                [0x62; 32],
                [0x63; 32],
                [0x66; 32],
                2,
                1,
                [0x71; 32],
            )
            .unwrap(),
            VerifiedProductionTraceV1::from_verified_parts(
                trusted.digest(),
                challenge.challenge_digest(),
                [0x62; 32],
                [0x63; 32],
                [0x64; 32],
                3,
                1,
                [0x71; 32],
            )
            .unwrap(),
            VerifiedProductionTraceV1::from_verified_parts(
                trusted.digest(),
                challenge.challenge_digest(),
                [0x62; 32],
                [0x63; 32],
                [0x64; 32],
                2,
                0,
                [0x71; 32],
            )
            .unwrap(),
        ] {
            let different =
                ProductionCommitmentWorkBindingV1::derive(challenge, &trusted, &different_identity)
                    .unwrap();
            assert_ne!(
                binding.proof_commitment_root,
                different.proof_commitment_root
            );
            assert_ne!(binding.work_digest, different.work_digest);
        }

        let different_output = ProductionCommitmentWorkBindingV1::derive(
            challenge,
            &trusted,
            &verified_trace(&trusted, challenge, [0x62; 32], [0x72; 32]),
        )
        .unwrap();
        assert_ne!(
            binding.proof_commitment_root,
            different_output.proof_commitment_root
        );
        assert_ne!(binding.work_digest, different_output.work_digest);

        let different_model =
            ProductionBatchedModelIdentityV1::from_unverified_ceremony_root(&model, [0x64; 32])
                .unwrap();
        assert_eq!(
            ProductionCommitmentWorkBindingV1::derive(challenge, &different_model, &trace),
            Err(ProductionWhirCandidateError::VerifiedTraceContextMismatch)
        );
        let different_model_trace =
            verified_trace(&different_model, challenge, [0x62; 32], [0x71; 32]);
        let different_model_binding = ProductionCommitmentWorkBindingV1::derive(
            challenge,
            &different_model,
            &different_model_trace,
        )
        .unwrap();
        assert_ne!(
            binding.proof_commitment_root,
            different_model_binding.proof_commitment_root
        );
        assert_ne!(binding.work_digest, different_model_binding.work_digest);

        assert_eq!(
            hex::encode(production_proof_binding_suite_digest_v1()),
            "c02aa7c5e803dfd877d1fd894bef02c818535b96136074fdfb11f1b7f7dfb7d1"
        );
        assert_eq!(
            hex::encode(trusted.digest()),
            "f73a6a68edda1ced67150695910ffdb09f2c8a5ad5fbf0c88ad6584c16f7b3bb"
        );
        assert_eq!(
            hex::encode(binding.proof_commitment_root.as_bytes()),
            "21056541061756523da50c1b2b36613f16743063c499f84baff63fc6e014992d"
        );
        assert_eq!(
            hex::encode(binding.work_digest),
            "48afbf18486659848824e8128080f0cb31177687f13445700abe2e6fa0d9073e"
        );
        assert_eq!(
            hex::encode(binding.public_binding),
            "c042a3cdd58a8fe8fc10cb47c77792f16179d51becd02ca124d9d92ef8aa5780"
        );
    }

    #[test]
    fn commitment_claim_verifier_rederives_roots_work_and_target() {
        let model = production_model();
        let trusted =
            ProductionBatchedModelIdentityV1::from_unverified_ceremony_root(&model, [0x61; 32])
                .unwrap();
        let challenge_digest = [0x11; 32];
        let target = [0xff; 32];
        let challenge = ProductionCommitmentChallengeV1::from_test_parts(challenge_digest, target);
        let trace = verified_trace(&trusted, challenge, [0x62; 32], [0x71; 32]);
        let expected =
            ProductionCommitmentWorkBindingV1::derive(challenge, &trusted, &trace).unwrap();
        let claims = expected.claims();
        verify_production_commitment_claims_v1(challenge, &trusted, &trace, &claims).unwrap();

        let mut wrong_root = claims;
        wrong_root.proof_commitment_root[0] ^= 1;
        assert_eq!(
            verify_production_commitment_claims_v1(challenge, &trusted, &trace, &wrong_root),
            Err(ProductionWhirCandidateError::ProofCommitmentMismatch)
        );

        let mut wrong_work = claims;
        wrong_work.work_digest[0] ^= 1;
        assert_eq!(
            verify_production_commitment_claims_v1(challenge, &trusted, &trace, &wrong_work),
            Err(ProductionWhirCandidateError::WorkDigestMismatch)
        );

        let mut wrong_binding = claims;
        wrong_binding.public_binding[0] ^= 1;
        assert_eq!(
            verify_production_commitment_claims_v1(challenge, &trusted, &trace, &wrong_binding,),
            Err(ProductionWhirCandidateError::PublicBindingMismatch)
        );
        let different_trace = verified_trace(&trusted, challenge, [0x65; 32], [0x71; 32]);
        assert_eq!(
            verify_production_commitment_claims_v1(challenge, &trusted, &different_trace, &claims,),
            Err(ProductionWhirCandidateError::ProofCommitmentMismatch)
        );

        let hard_target = [0; 32];
        let hard_challenge =
            ProductionCommitmentChallengeV1::from_test_parts(challenge_digest, hard_target);
        let high_hash = ProductionCommitmentWorkBindingV1::derive(hard_challenge, &trusted, &trace)
            .unwrap()
            .claims();
        assert_eq!(
            verify_production_commitment_claims_v1(hard_challenge, &trusted, &trace, &high_hash,),
            Err(ProductionWhirCandidateError::HighHash)
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
