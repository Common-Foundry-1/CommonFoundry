//! Canonical shared-layout boundary for the BLS12-381 proof components.
//!
//! Matrix, transition, and wiring commitments must use one variable count before
//! their openings can be reduced by a single Dory aggregate. This module pins
//! the production n=33 geometry, composes transition arithmetic with the range
//! checkpoint against one commitment, and binds every component opening into a
//! single aggregate.

use std::io::{Cursor, Read};
use std::path::Path;

use dory_pcs::primitives::{
    DoryDeserialize, DorySerialize,
    arithmetic::{Field, Group},
    serialization::{Compress, Validate},
    transcript::Transcript,
};
use thiserror::Error;

use crate::{
    ModelBankFieldStreamError, ModelBankManifest, ModelFieldChunk, ModelPcsIdentity, ModelPcsRole,
    PRODUCTION_V2_BANKS, PRODUCTION_V2_BATCH, PRODUCTION_V2_DIMENSION,
    PRODUCTION_V2_LAYERS_PER_BANK, STRUCTURED_TRANSITION_ACTIVATION_ORACLE,
    STRUCTURED_TRANSITION_INPUT_ORACLE, STRUCTURED_TRANSITION_ORACLES,
    STRUCTURED_TRANSITION_REGULAR_ORACLES, StagedModelFieldSink, StructuredMaskPolynomial,
    StructuredMatrixStatement, StructuredTransitionStatement, StructuredTransitionWitness,
    StructuredWiringStatement, VerifiedModelBankReceipt,
    dory_bls12_381_aggregate::{
        BlsDoryAggregateError, BlsDoryAggregateLayout, BlsDoryCommittedPolynomial,
        BlsDoryCommittedPolynomialWriter, BlsDoryDeferredOpeningSet, BlsDoryOpeningClaim,
        MAX_BLS_DORY_AGGREGATE_BYTES, commit_bls_dory_polynomial,
        commit_bls_dory_row_source_with_scratch, projected_bls_dory_aggregate_bytes,
        prove_bls_dory_deferred_opening_sets_consuming,
        prove_bls_dory_deferred_opening_sets_consuming_with_scratch,
        regenerate_bls_dory_compact_row_source_with_scratch, verify_bls_dory_openings,
    },
    dory_bls12_381_compact_artifact::BlsDoryCompactArtifactSpec,
    dory_bls12_381_fold_artifact::BlsDoryFoldArtifactSpec,
    dory_bls12_381_logup::{
        BLS_DORY_RANGE_LOGUP_OPENING_CLAIMS, BLS_DORY_RANGE_LOGUP_TABLE_VALUES,
        BlsDoryRangeLogUpError, BlsDoryRangeLogUpProof, PreparedBlsDoryRangeLogUpProof,
        projected_production_range_logup_opening_bytes,
        projected_production_range_logup_proof_bytes, prove_bls_dory_range_logup,
        prove_bls_dory_range_logup_at_variables, prove_bls_dory_range_logup_deferred_at_variables,
        prove_bls_dory_range_logup_deferred_with_precommitted_compact_transition_and_scratch,
        prove_bls_dory_range_logup_deferred_with_precommitted_transition_and_scratch,
        verify_bls_dory_range_logup, verify_bls_dory_range_logup_at_variables,
        verify_bls_dory_range_logup_deferred_at_variables,
    },
    dory_bls12_381_matrix::{
        BlsDoryMatrixError, BlsDoryMatrixProof, PreparedBlsDoryMatrixProof,
        projected_production_matrix_opening_bytes, projected_production_matrix_proof_bytes,
        prove_bls_dory_matrix_deferred_at_variables,
        prove_bls_dory_matrix_deferred_at_variables_with_scratch,
        prove_bls_dory_matrix_deferred_with_precommitted_weight_and_scratch,
        verify_bls_dory_matrix_deferred_at_variables,
    },
    dory_bls12_381_prototype::{
        BlsDoryFr, BlsDoryG1, BlsDoryGt, BlsDoryTranscript, DeterministicBlsDorySetup,
    },
    dory_bls12_381_streaming::BlsDoryRowSource,
    dory_bls12_381_transition::{
        BLS_DORY_TRANSITION_OPENING_CLAIMS, BlsDoryTransitionError, BlsDoryTransitionProof,
        BlsDoryTransitionWitnessRowSource, PRODUCTION_TRANSITION_WORD_WIDTH_CODES,
        PreparedBlsDoryTransitionProof, TRANSITION_SIGNED_WORD_SELECTORS,
        projected_production_transition_opening_bytes, projected_production_transition_proof_bytes,
        prove_bls_dory_transition, prove_bls_dory_transition_at_variables,
        prove_bls_dory_transition_deferred_at_variables,
        prove_bls_dory_transition_deferred_at_variables_with_scratch, verify_bls_dory_transition,
        verify_bls_dory_transition_at_variables, verify_bls_dory_transition_deferred_at_variables,
    },
    dory_bls12_381_wiring::{
        BlsDoryWiringError, BlsDoryWiringProof, PreparedBlsDoryWiringProof,
        projected_production_wiring_opening_bytes, projected_production_wiring_proof_bytes,
        prove_bls_dory_wiring_deferred_at_variables,
        prove_bls_dory_wiring_deferred_at_variables_with_scratch,
        verify_bls_dory_wiring_deferred_at_variables,
    },
    dory_v3_model::DoryV3ModelIdentityV1,
    dory_v3_model_record::BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    dory_v3_suite::{
        DORY_V3_FIXED_MODEL_BINDING_DOMAIN, DORY_V3_FIXED_MODEL_BINDING_VERSION,
        DORY_V3_NATIVE_COMPOSITION_BINDING_DOMAIN, DORY_V3_NATIVE_COMPOSITION_VERSION,
        DORY_V3_PADDED_VARIABLES, DORY_V3_PRODUCTION_SUITE_DIGEST, DORY_V3_SETUP_IDENTITY,
        DORY_V3_SHARED_LAYOUT_VERSION, DORY_V3_SHARED_OPENING_BINDING_DOMAIN, Digest32,
    },
    model_bank::{
        StagedModelFieldLayoutSink, VerifiedModelBankLayoutReceipt,
        verify_model_bank_into_staged_field_layout_sink,
    },
    structured_proof::StructuredForgeMatrixResearchShape,
    structured_wiring::{validate_streaming_tables, validate_successors},
    sumcheck::GOLDILOCKS_MODULUS,
    verify_model_bank_into_staged_field_sink,
};

#[cfg(feature = "whir-prototype")]
use crate::{
    dory_bls12_381_blake3::{
        PreparedBlsDoryNativeBlake3Opening, prepare_production_dory_v3_native_blake3_opening,
        verify_encoded_dory_v3_native_blake3_opening_statement,
        verify_encoded_native_blake3_opening_statement,
    },
    dory_bls12_381_output_bridge::{BlsDoryOutputBridgeError, BlsDoryOutputBridgeStatement},
};

#[cfg(any(test, feature = "whir-prototype"))]
use crate::{
    dory_bls12_381_aggregate::{
        BLS_DORY_AGGREGATE_VERSION, BLS_DORY_COMPOSED_AGGREGATE_CLAIMS,
        prove_bls_dory_deferred_opening_sets_consuming_composed, verify_bls_dory_composed_openings,
    },
    dory_bls12_381_blake3::{
        BLS_DORY_BLAKE3_COMPOSED_OPENING_CLAIMS, BLS_DORY_BLAKE3_PROJECTION_VERSION,
        BlsDoryBlake3OpeningStatement,
    },
    dory_bls12_381_execution_artifact::{
        BlsDoryExecutionAccumulatorArtifact, BlsDoryExecutionAccumulatorArtifactContext,
        BlsDoryExecutionAccumulatorColumn,
    },
    dory_bls12_381_logup::prove_bls_dory_range_logup_deferred_with_precommitted_row_source_and_scratch,
    dory_bls12_381_matrix::{
        BlsDoryExecutionArtifactMatrixInput,
        prove_bls_dory_matrix_deferred_with_precommitted_weight_from_execution_artifact_and_scratch,
    },
    dory_bls12_381_transition::{
        BlsDoryExecutionAccumulatorTransition, derive_transition_regular_row_from_mask,
        prove_bls_dory_transition_deferred_from_execution_artifact_with_scratch,
        regenerate_bls_dory_transition_compact_source_from_execution_artifact_with_scratch,
    },
    dory_bls12_381_wiring::prove_bls_dory_wiring_deferred_from_execution_artifact_with_scratch,
};

#[cfg(all(test, feature = "whir-prototype"))]
use crate::dory_bls12_381_blake3::verify_encoded_native_blake3_test_opening_statement_at_layout;

pub const BLS_DORY_SHARED_LAYOUT_VERSION: u16 = 4;
pub const BLS_DORY_FIXED_MODEL_IDENTITY_VERSION: u16 = 1;
pub const BLS_DORY_FINAL_OUTPUT_BRIDGE_VERSION: u16 = 1;
pub(crate) const MAX_SHARED_LAYOUT_BINDING_BYTES: usize = 4_096;
pub(crate) const SHARED_PROOF_MAGIC: [u8; 8] = *b"CFBLSS01";
const SHARED_PROOF_HEADER_BYTES: usize = 16;
pub const MAX_BLS_DORY_SHARED_MATRIX_PROOFS: usize = 3;
pub const MAX_BLS_DORY_SHARED_TRANSITION_PROOFS: usize = 4;
pub const MAX_BLS_DORY_SHARED_LAYOUT_PROOF_BYTES: usize = 262_128;
pub const BLS_DORY_SHARED_INITIALIZATION_LINKS: usize = 2;
pub const BLS_DORY_SHARED_LINKS_PER_BANK: usize = 3;
const BLS_DORY_SHARED_SOURCE_FOLD_GENERATIONS: u32 = 8;

pub(crate) const BLS_DORY_SHARED_NATIVE_COMPOSITION_VERSION: u16 = 1;
pub(crate) const BLS_DORY_SHARED_NATIVE_COMPOSITION_CLAIMS: usize = 6;

/// Bank-authenticated public inputs for the Dory-native shared Layout V5
/// transcripts.
///
/// Construction requires the non-serializable capability produced after one
/// complete model-bank reader has reproduced every ordered Record V2
/// commitment. The context deliberately carries no legacy V4 identity or
/// binding state.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlsDorySharedLayoutV5Context {
    suite_digest: Digest32,
    model_identity_digest: Digest32,
    setup_identity: Digest32,
    padded_variables: u32,
}

/// Typed output of the fixed-model Binding V2 transcript. A shared Layout V5
/// opening can only be derived from this value, preventing a legacy V4 binding
/// or an unrelated 32-byte digest from being substituted accidentally.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlsDoryFixedModelBindingV2([u8; 32]);

impl BlsDoryFixedModelBindingV2 {
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Typed output of the shared-opening Layout V5 transcript. Native composition
/// accepts this value rather than an untyped digest so its shared prefix cannot
/// be replaced with a V4 opening binding.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlsDorySharedOpeningBindingV5([u8; 32]);

impl BlsDorySharedOpeningBindingV5 {
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl BlsDorySharedLayoutV5Context {
    /// Copy the exact Record V2 identities only after the record has passed the
    /// compiled production suite, setup, geometry, manifest, and commitment
    /// checks represented by the bank-authentication capability.
    pub fn from_bank_authenticated_record(
        authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<Self, BlsDorySharedLayoutError> {
        let record = authenticated.record();
        record
            .validate_production(setup)
            .map_err(|_| BlsDorySharedLayoutError::V3Context)?;
        Ok(Self {
            suite_digest: record.suite_digest(),
            model_identity_digest: record.model_identity_digest(),
            setup_identity: record.setup_identity(),
            padded_variables: record.padded_variables(),
        })
    }

    #[cfg(all(test, feature = "whir-prototype"))]
    pub(crate) fn from_bank_authenticated_record_for_test(
        authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<Self, BlsDorySharedLayoutError> {
        let record = authenticated.record();
        if record.setup_identity().into_bytes() != setup.identity()
            || usize::try_from(record.padded_variables()).ok() != Some(setup.max_log_n())
        {
            return Err(BlsDorySharedLayoutError::V3Context);
        }
        Ok(Self {
            suite_digest: record.suite_digest(),
            model_identity_digest: record.model_identity_digest(),
            setup_identity: record.setup_identity(),
            padded_variables: record.padded_variables(),
        })
    }

    pub const fn suite_digest(self) -> Digest32 {
        self.suite_digest
    }

    pub const fn model_identity_digest(self) -> Digest32 {
        self.model_identity_digest
    }

    pub const fn setup_identity(self) -> Digest32 {
        self.setup_identity
    }

    pub const fn padded_variables(self) -> u32 {
        self.padded_variables
    }

    /// Derive the exact fixed-model Binding V2 transcript frozen by
    /// `DORY_V3_FIXED_MODEL_BINDING_FIELDS`.
    pub fn fixed_model_binding(
        self,
        outer_binding: &[u8],
    ) -> Result<BlsDoryFixedModelBindingV2, BlsDorySharedLayoutError> {
        if outer_binding.len() > MAX_SHARED_LAYOUT_BINDING_BYTES {
            return Err(BlsDorySharedLayoutError::InvalidProofShape);
        }
        let outer_binding_length = u32::try_from(outer_binding.len())
            .map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)?;
        let mut hasher = blake3::Hasher::new_derive_key(DORY_V3_FIXED_MODEL_BINDING_DOMAIN);
        hasher.update(&DORY_V3_FIXED_MODEL_BINDING_VERSION.to_le_bytes());
        hasher.update(&DORY_V3_SHARED_LAYOUT_VERSION.to_le_bytes());
        hasher.update(self.suite_digest.as_bytes());
        hasher.update(self.model_identity_digest.as_bytes());
        hasher.update(self.setup_identity.as_bytes());
        hasher.update(&self.padded_variables.to_le_bytes());
        hasher.update(&outer_binding_length.to_le_bytes());
        hasher.update(outer_binding);
        Ok(BlsDoryFixedModelBindingV2(*hasher.finalize().as_bytes()))
    }

    /// Derive the exact shared-opening Layout V5 transcript from the ordered
    /// component transcript digests. The V3 production suite has exactly three
    /// matrix proofs followed by four arithmetic/range transition pairs.
    pub fn shared_opening_binding(
        self,
        component_binding: BlsDoryFixedModelBindingV2,
        matrices: &[&BlsDoryMatrixProof],
        transitions: &[(&BlsDoryTransitionProof, &BlsDoryRangeLogUpProof)],
        wiring: &BlsDoryWiringProof,
    ) -> Result<BlsDorySharedOpeningBindingV5, BlsDorySharedLayoutError> {
        let matrix_transcript_digests = matrices
            .iter()
            .map(|proof| proof.transcript_digest)
            .collect::<Vec<_>>();
        let transition_transcript_digests = transitions
            .iter()
            .map(|(arithmetic, range)| (arithmetic.transcript_digest, range.transcript_digest))
            .collect::<Vec<_>>();
        self.shared_opening_binding_from_digests(
            component_binding,
            &matrix_transcript_digests,
            &transition_transcript_digests,
            wiring.transcript_digest,
        )
    }

    fn shared_opening_binding_from_digests(
        self,
        component_binding: BlsDoryFixedModelBindingV2,
        matrix_transcript_digests: &[[u8; 32]],
        transition_transcript_digests: &[([u8; 32], [u8; 32])],
        wiring_transcript_digest: [u8; 32],
    ) -> Result<BlsDorySharedOpeningBindingV5, BlsDorySharedLayoutError> {
        if matrix_transcript_digests.len() != MAX_BLS_DORY_SHARED_MATRIX_PROOFS
            || transition_transcript_digests.len() != MAX_BLS_DORY_SHARED_TRANSITION_PROOFS
        {
            return Err(BlsDorySharedLayoutError::InvalidProofShape);
        }
        let matrix_count = u16::try_from(matrix_transcript_digests.len())
            .map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)?;
        let transition_count = u16::try_from(transition_transcript_digests.len())
            .map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)?;
        let mut hasher = blake3::Hasher::new_derive_key(DORY_V3_SHARED_OPENING_BINDING_DOMAIN);
        hasher.update(&DORY_V3_SHARED_LAYOUT_VERSION.to_le_bytes());
        hasher.update(&self.padded_variables.to_le_bytes());
        hasher.update(self.setup_identity.as_bytes());
        hasher.update(component_binding.as_bytes());
        hasher.update(&matrix_count.to_le_bytes());
        for transcript_digest in matrix_transcript_digests {
            hasher.update(transcript_digest);
        }
        hasher.update(&transition_count.to_le_bytes());
        for (arithmetic_transcript_digest, range_transcript_digest) in transition_transcript_digests
        {
            hasher.update(arithmetic_transcript_digest);
            hasher.update(range_transcript_digest);
        }
        hasher.update(&wiring_transcript_digest);
        Ok(BlsDorySharedOpeningBindingV5(*hasher.finalize().as_bytes()))
    }

    /// Derive the exact native-composition Binding V1 transcript for the
    /// canonical Dory row/column split of this Layout V5 context.
    pub fn native_composition_binding(
        self,
        shared_opening_binding: BlsDorySharedOpeningBindingV5,
        native_opening_binding: [u8; 32],
        layout: BlsDoryAggregateLayout,
    ) -> Result<[u8; 32], BlsDorySharedLayoutError> {
        if native_opening_binding == [0; 32] {
            return Err(BlsDorySharedLayoutError::OpeningClaims);
        }
        let padded_variables = usize::try_from(self.padded_variables)
            .map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)?;
        let expected_nu = padded_variables / 2;
        let expected_sigma = padded_variables - expected_nu;
        if layout.nu() != expected_nu || layout.sigma() != expected_sigma {
            return Err(BlsDorySharedLayoutError::InvalidProofShape);
        }
        let dory_nu =
            u16::try_from(layout.nu()).map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)?;
        let dory_sigma = u16::try_from(layout.sigma())
            .map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)?;
        let mut hasher = blake3::Hasher::new_derive_key(DORY_V3_NATIVE_COMPOSITION_BINDING_DOMAIN);
        hasher.update(&DORY_V3_SHARED_LAYOUT_VERSION.to_le_bytes());
        hasher.update(&DORY_V3_NATIVE_COMPOSITION_VERSION.to_le_bytes());
        hasher.update(&dory_nu.to_le_bytes());
        hasher.update(&dory_sigma.to_le_bytes());
        hasher.update(self.setup_identity.as_bytes());
        hasher.update(shared_opening_binding.as_bytes());
        hasher.update(&native_opening_binding);
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Maximum variable count across production matrix, transition, and wiring tables.
pub const BLS_DORY_SHARED_PRODUCTION_VARIABLES: usize = 33;
/// Three matrix banks each expose activation, weight, and accumulator openings.
pub const BLS_DORY_SHARED_PRODUCTION_MATRIX_CLAIMS: usize = 9;
/// The initialization transition and three matrix-bank transitions expose 110 claims each.
pub const BLS_DORY_SHARED_PRODUCTION_TRANSITION_CLAIMS: usize = 4 * STRUCTURED_TRANSITION_ORACLES;
/// Production wiring uses one initialization opening and ten openings per bank.
pub const BLS_DORY_SHARED_PRODUCTION_WIRING_CLAIMS: usize = 31;
/// Current direct terminal set before packed LogUp compression.
pub const BLS_DORY_SHARED_PRODUCTION_DIRECT_CLAIMS: usize = BLS_DORY_SHARED_PRODUCTION_MATRIX_CLAIMS
    + BLS_DORY_SHARED_PRODUCTION_TRANSITION_CLAIMS
    + BLS_DORY_SHARED_PRODUCTION_WIRING_CLAIMS;
/// Four scalar range checkpoints need four openings each.
pub const BLS_DORY_SHARED_LOGUP_RANGE_TRANSITION_CLAIMS: usize =
    4 * BLS_DORY_RANGE_LOGUP_OPENING_CLAIMS;
/// Four arithmetic transition checkpoints retain twelve regular openings each.
pub const BLS_DORY_SHARED_ARITHMETIC_TRANSITION_CLAIMS: usize =
    4 * BLS_DORY_TRANSITION_OPENING_CLAIMS;
/// Arithmetic plus compressed range claims across all four transitions.
pub const BLS_DORY_SHARED_COMPRESSED_TRANSITION_CLAIMS: usize =
    BLS_DORY_SHARED_ARITHMETIC_TRANSITION_CLAIMS + BLS_DORY_SHARED_LOGUP_RANGE_TRANSITION_CLAIMS;
/// Complete claim count after packed range compression.
pub const BLS_DORY_SHARED_COMPRESSED_CHECKPOINT_CLAIMS: usize =
    BLS_DORY_SHARED_PRODUCTION_MATRIX_CLAIMS
        + BLS_DORY_SHARED_COMPRESSED_TRANSITION_CLAIMS
        + BLS_DORY_SHARED_PRODUCTION_WIRING_CLAIMS;
/// One initialization equality plus three matrix/transition/wiring equalities per bank.
pub const BLS_DORY_SHARED_PRODUCTION_EQUALITY_LINKS: usize = BLS_DORY_SHARED_INITIALIZATION_LINKS
    + MAX_BLS_DORY_SHARED_MATRIX_PROOFS * BLS_DORY_SHARED_LINKS_PER_BANK;
/// Each equality opens both independently committed representations at one point.
pub const BLS_DORY_SHARED_PRODUCTION_EQUALITY_CLAIMS: usize =
    2 * BLS_DORY_SHARED_PRODUCTION_EQUALITY_LINKS;
/// The final-output bridge opens the last transition and wiring output at the
/// same challenge-derived cell point.
pub const BLS_DORY_SHARED_FINAL_OUTPUT_BRIDGE_CLAIMS: usize = 2;
/// Complete production claim count after range compression and equality links.
pub const BLS_DORY_SHARED_PRODUCTION_CLAIMS: usize = BLS_DORY_SHARED_COMPRESSED_CHECKPOINT_CLAIMS
    + BLS_DORY_SHARED_PRODUCTION_EQUALITY_CLAIMS
    + BLS_DORY_SHARED_FINAL_OUTPUT_BRIDGE_CLAIMS;
#[cfg(any(test, feature = "whir-prototype"))]
const _: () = {
    assert!(BLS_DORY_SHARED_PRODUCTION_CLAIMS == 128);
    assert!(BLS_DORY_SHARED_NATIVE_COMPOSITION_CLAIMS == 6);
    assert!(BLS_DORY_BLAKE3_COMPOSED_OPENING_CLAIMS == 134);
    assert!(BLS_DORY_COMPOSED_AGGREGATE_CLAIMS == 134);
    assert!(
        BLS_DORY_SHARED_PRODUCTION_CLAIMS + BLS_DORY_SHARED_NATIVE_COMPOSITION_CLAIMS
            == BLS_DORY_BLAKE3_COMPOSED_OPENING_CLAIMS
    );
};
/// Shared transport is not yet accepted by consensus.
pub const BLS_DORY_SHARED_LAYOUT_PRODUCTION_READY: bool = false;
/// Remaining gates on the shared scalar layout.
pub const BLS_DORY_SHARED_LAYOUT_PRODUCTION_BLOCKERS: [&str; 2] = [
    "the final model bank lacks pinned n=33 BLS commitments; bounded parallel writers, shared compact transition/mapped sources with authenticated per-selector transition words and packed radix-16 nibbles, one-byte bounded activation, wiring, and model-weight sources after their first Dory row, signed-word accumulator sources, authenticated release/regeneration, and eight challenge-bound source-fold views preserve exact proofs, but the exact complete aggregate-stage projection remains 29,202,416,244 bytes (about 27.2 GiB) and the complete n=33 prover has not been run",
    "the complete shared transcript, soundness accounting, and implementation have not received independent audit",
];

/// Exact on-disk accounting for the current scratch-backed production topology.
///
/// The aggregate keeps every committed coefficient source live while it folds
/// each unique polynomial. This projection follows every generation in table
/// order and accounts for the child being fully written before its parent is
/// deleted. Input model-bank bytes and in-memory Dory row commitments are not
/// included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlsDorySharedProductionScratchProjection {
    pub matrix_source_bytes: u64,
    pub transition_source_bytes: u64,
    pub multiplicity_source_bytes: u64,
    pub wiring_source_bytes: u64,
    pub fixed_base_source_bytes: u64,
    pub retained_source_bytes: u64,
    pub matrix_first_fold_bytes: u64,
    pub transition_first_fold_bytes: u64,
    pub multiplicity_first_fold_bytes: u64,
    pub wiring_first_fold_bytes: u64,
    pub fixed_base_first_fold_bytes: u64,
    pub first_generation_fold_bytes: u64,
    pub fifth_generation_fold_bytes: u64,
    pub source_materialization_fold_bytes: u64,
    pub aggregate_fold_peak_bytes: u64,
    pub aggregate_peak_bytes: u64,
}

/// Network-pinned BLS commitments for the authenticated fixed model.
///
/// The descriptor is supplied by the trusted consensus configuration, never by
/// the block proof. Its model digest binds the existing byte/WHIR identity while
/// the Dory commitments bind the scalar tables used by this proof backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsDoryFixedModelIdentity {
    pub protocol_version: u16,
    pub model_pcs_identity_digest: [u8; 32],
    pub setup_identity: [u8; 32],
    pub base_input_commitment: BlsDoryGt,
    pub weight_bank_commitments: Vec<BlsDoryGt>,
}

impl BlsDoryFixedModelIdentity {
    pub fn validate(
        &self,
        trusted_model: &ModelPcsIdentity,
        expected_banks: usize,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<(), BlsDorySharedLayoutError> {
        setup
            .validate()
            .map_err(|_| BlsDorySharedLayoutError::FixedModelIdentity)?;
        let model_digest = trusted_model
            .digest()
            .map_err(|_| BlsDorySharedLayoutError::FixedModelIdentity)?;
        if self.protocol_version != BLS_DORY_FIXED_MODEL_IDENTITY_VERSION
            || self.model_pcs_identity_digest != model_digest
            || self.setup_identity != setup.identity()
            || self.weight_bank_commitments.len() != expected_banks
            || self.weight_bank_commitments.len() != trusted_model.weight_bank_commitments.len()
            || self.base_input_commitment == BlsDoryGt::identity()
            || self
                .weight_bank_commitments
                .iter()
                .any(|commitment| *commitment == BlsDoryGt::identity())
        {
            return Err(BlsDorySharedLayoutError::FixedModelIdentity);
        }
        for (index, commitment) in self.weight_bank_commitments.iter().enumerate() {
            if *commitment == self.base_input_commitment
                || self.weight_bank_commitments[..index].contains(commitment)
            {
                return Err(BlsDorySharedLayoutError::FixedModelIdentity);
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32], BlsDorySharedLayoutError> {
        let bank_count = u16::try_from(self.weight_bank_commitments.len())
            .map_err(|_| BlsDorySharedLayoutError::FixedModelIdentity)?;
        let mut encoded = Vec::new();
        append_serialized(&mut encoded, &self.base_input_commitment)?;
        for commitment in &self.weight_bank_commitments {
            append_serialized(&mut encoded, commitment)?;
        }
        let mut hasher = blake3::Hasher::new_derive_key(
            "CommonFoundry/ForgeMatrix/BlsDoryFixedModelIdentity/v1",
        );
        hasher.update(&self.protocol_version.to_le_bytes());
        hasher.update(&bank_count.to_le_bytes());
        hasher.update(&self.model_pcs_identity_digest);
        hasher.update(&self.setup_identity);
        hasher.update(&encoded);
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Derive the network-pinned Dory commitments from already authenticated model
/// values. Production must call this through the streamed model-bank boundary;
/// this bounded reference helper exists for fixtures and activation tooling.
pub fn derive_bls_dory_fixed_model_identity(
    trusted_model: &ModelPcsIdentity,
    base_input: &[i64],
    weight_banks: &[&[i64]],
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryFixedModelIdentity, BlsDorySharedLayoutError> {
    trusted_model
        .validate()
        .map_err(|_| BlsDorySharedLayoutError::FixedModelIdentity)?;
    setup
        .validate()
        .map_err(|_| BlsDorySharedLayoutError::FixedModelIdentity)?;
    if weight_banks.len() != trusted_model.weight_bank_commitments.len()
        || padded_variables > setup.max_log_n()
    {
        return Err(BlsDorySharedLayoutError::FixedModelIdentity);
    }
    let base_elements = usize::try_from(
        u64::from(trusted_model.batch)
            .checked_mul(u64::from(trusted_model.dimension))
            .ok_or(BlsDorySharedLayoutError::FixedModelIdentity)?,
    )
    .map_err(|_| BlsDorySharedLayoutError::FixedModelIdentity)?;
    let weight_elements = usize::try_from(
        u64::from(trusted_model.layers_per_bank)
            .checked_mul(u64::from(trusted_model.dimension))
            .and_then(|value| value.checked_mul(u64::from(trusted_model.dimension)))
            .ok_or(BlsDorySharedLayoutError::FixedModelIdentity)?,
    )
    .map_err(|_| BlsDorySharedLayoutError::FixedModelIdentity)?;
    if base_input.len() != base_elements
        || weight_banks
            .iter()
            .any(|weights| weights.len() != weight_elements)
    {
        return Err(BlsDorySharedLayoutError::FixedModelIdentity);
    }
    let base_input_commitment =
        commit_fixed_table(base_input, padded_variables, setup)?.commitment();
    let weight_bank_commitments = weight_banks
        .iter()
        .map(|weights| {
            commit_fixed_table(weights, padded_variables, setup)
                .map(|committed| committed.commitment())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let identity = BlsDoryFixedModelIdentity {
        protocol_version: BLS_DORY_FIXED_MODEL_IDENTITY_VERSION,
        model_pcs_identity_digest: trusted_model
            .digest()
            .map_err(|_| BlsDorySharedLayoutError::FixedModelIdentity)?,
        setup_identity: setup.identity(),
        base_input_commitment,
        weight_bank_commitments,
    };
    identity.validate(trusted_model, weight_banks.len(), setup)?;
    Ok(identity)
}

/// Authenticate one canonical model bank and derive its BLS commitments without
/// materializing any fixed polynomial.
///
/// Chunks remain provisional until the model-bank verifier checks the trusted
/// roots, exact payload length, and EOF. The returned identity is therefore the
/// only publication point for the incrementally accumulated commitments.
pub fn derive_bls_dory_fixed_model_identity_from_verified_bank<R: Read>(
    reader: R,
    expected_manifest: &ModelBankManifest,
    trusted_model: &ModelPcsIdentity,
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryFixedModelIdentity, ModelBankFieldStreamError<BlsDoryFixedModelStreamError>> {
    let sink = BlsDoryFixedModelSink::new(trusted_model, padded_variables, setup)
        .map_err(ModelBankFieldStreamError::Sink)?;
    verify_model_bank_into_staged_field_sink(reader, expected_manifest, trusted_model, sink)
}

/// Commitments rederived from one completely authenticated model-bank reader.
///
/// This crate-private value deliberately carries no legacy `ModelPcsIdentity`:
/// Record V2 compares each ordered commitment against the independently pinned
/// Dory V3 identity before publishing an authenticated capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BlsDoryDerivedModelCommitments {
    pub(crate) base_input: BlsDoryGt,
    pub(crate) weight_banks: Vec<BlsDoryGt>,
}

/// Authenticate one canonical model bank and transactionally rederive the
/// ordered Dory commitments for an explicitly supplied role layout.
///
/// Geometry and setup checks run before the reader is touched. Chunks remain
/// provisional inside the sink, and no commitment is returned unless the same
/// reader authenticates the complete header, payload, roots, length, and EOF.
#[allow(clippy::too_many_arguments)]
pub(crate) fn derive_bls_dory_model_commitments_from_verified_layout<R: Read>(
    reader: R,
    expected_manifest: &ModelBankManifest,
    batch: u32,
    dimension: u32,
    layers_per_bank: u32,
    weight_bank_count: u32,
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryDerivedModelCommitments, ModelBankFieldStreamError<BlsDoryFixedModelStreamError>>
{
    let sink = BlsDoryModelLayoutSink::new(
        expected_manifest,
        batch,
        dimension,
        layers_per_bank,
        weight_bank_count,
        padded_variables,
        setup,
    )
    .map_err(ModelBankFieldStreamError::Sink)?;
    verify_model_bank_into_staged_field_layout_sink(
        reader,
        expected_manifest,
        layers_per_bank,
        weight_bank_count,
        sink,
    )
}

/// Authenticated fixed-model commitments plus reusable coefficient artifacts.
/// Dropping this capability removes its owned scratch files after every matrix
/// and shared opening clone has also been dropped.
#[derive(Debug)]
pub struct BlsDoryPreparedFixedModel {
    identity: BlsDoryFixedModelIdentity,
    base_input: BlsDoryCommittedPolynomial,
    weight_banks: Vec<BlsDoryCommittedPolynomial>,
}

/// Bank-authenticated Dory V3 fixed-model commitments plus reusable
/// coefficient artifacts.
///
/// The exact Record V2 and model-identity bindings remain private. Callers can
/// only test them against another non-serializable bank-authenticated record,
/// so serialized audit records cannot substitute for the reader-authenticated
/// capability used to prepare these polynomials.
#[derive(Debug)]
pub struct BlsDoryPreparedFixedModelV5 {
    record_digest: Digest32,
    model_identity_digest: Digest32,
    model_identity: DoryV3ModelIdentityV1,
    #[allow(dead_code, reason = "consumed by the in-module V5 prover integration")]
    base_input: BlsDoryCommittedPolynomial,
    #[allow(dead_code, reason = "consumed by the in-module V5 prover integration")]
    weight_banks: Vec<BlsDoryCommittedPolynomial>,
}

impl BlsDoryPreparedFixedModelV5 {
    #[must_use]
    pub const fn record_digest(&self) -> Digest32 {
        self.record_digest
    }

    #[must_use]
    pub const fn model_identity_digest(&self) -> Digest32 {
        self.model_identity_digest
    }

    /// Return true only when this prepared model belongs to the exact same
    /// bank-authenticated Record V2 and immutable Dory V3 model identity.
    #[must_use]
    pub fn is_bound_to_bank_authenticated_record(
        &self,
        authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    ) -> bool {
        let record = authenticated.record();
        self.is_bound_to_record_parts(
            record.record_digest(),
            record.model_identity_digest(),
            record.model_identity(),
        )
    }

    fn is_bound_to_record_parts(
        &self,
        record_digest: Digest32,
        model_identity_digest: Digest32,
        model_identity: &DoryV3ModelIdentityV1,
    ) -> bool {
        self.record_digest == record_digest
            && self.model_identity_digest == model_identity_digest
            && &self.model_identity == model_identity
    }
}

impl BlsDoryPreparedFixedModel {
    #[must_use]
    pub const fn identity(&self) -> &BlsDoryFixedModelIdentity {
        &self.identity
    }

    #[must_use]
    pub const fn base_input(&self) -> &BlsDoryCommittedPolynomial {
        &self.base_input
    }

    #[must_use]
    pub fn weight_banks(&self) -> &[BlsDoryCommittedPolynomial] {
        &self.weight_banks
    }
}

/// Authenticate one canonical model bank and transactionally publish the exact
/// coefficient artifacts later consumed by matrix proving and aggregation.
/// No identity or polynomial escapes if the bank, sink, or EOF check fails.
pub fn prepare_bls_dory_fixed_model_from_verified_bank_with_scratch<R: Read>(
    reader: R,
    expected_manifest: &ModelBankManifest,
    trusted_model: &ModelPcsIdentity,
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<BlsDoryPreparedFixedModel, ModelBankFieldStreamError<BlsDoryFixedModelStreamError>> {
    let sink = BlsDoryPreparedFixedModelSink::new(
        trusted_model,
        padded_variables,
        setup,
        scratch_directory,
    )
    .map_err(ModelBankFieldStreamError::Sink)?;
    verify_model_bank_into_staged_field_sink(reader, expected_manifest, trusted_model, sink)
}

/// Reauthenticate one production Dory V3 model-bank reader and
/// transactionally publish the exact reusable coefficient artifacts bound to
/// its non-serializable Record V2 capability.
///
/// The staged polynomials remain private to the verifier until the bank header,
/// payload roots, exact length, and EOF have authenticated. The publication
/// step then compares the base commitment and every ordered weight-bank
/// commitment individually against the immutable Dory V3 model identity.
pub fn prepare_bls_dory_v3_fixed_model_from_bank_authenticated_record_with_scratch<R: Read>(
    reader: R,
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<BlsDoryPreparedFixedModelV5, ModelBankFieldStreamError<BlsDoryFixedModelStreamError>> {
    let record = authenticated.record();
    record.validate_production(setup).map_err(|_| {
        ModelBankFieldStreamError::Sink(BlsDoryFixedModelStreamError::InvalidIdentity)
    })?;
    let identity = record.model_identity();
    let weight_bank_count = identity.weight_bank_count().map_err(|_| {
        ModelBankFieldStreamError::Sink(BlsDoryFixedModelStreamError::InvalidIdentity)
    })?;
    let sink = BlsDoryPreparedFixedModelV5Sink::new(
        record.manifest(),
        identity,
        record.record_digest(),
        record.model_identity_digest(),
        setup,
        scratch_directory,
    )
    .map_err(ModelBankFieldStreamError::Sink)?;
    verify_model_bank_into_staged_field_layout_sink(
        reader,
        record.manifest(),
        identity.layers_per_bank(),
        weight_bank_count,
        sink,
    )
}

#[cfg(all(test, feature = "whir-prototype"))]
pub(crate) fn prepare_bls_dory_v3_fixed_model_from_bank_authenticated_record_for_test_with_scratch<
    R: Read,
>(
    reader: R,
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<BlsDoryPreparedFixedModelV5, ModelBankFieldStreamError<BlsDoryFixedModelStreamError>> {
    let record = authenticated.record();
    if record.setup_identity().into_bytes() != setup.identity()
        || usize::try_from(record.padded_variables()).ok() != Some(setup.max_log_n())
    {
        return Err(ModelBankFieldStreamError::Sink(
            BlsDoryFixedModelStreamError::InvalidIdentity,
        ));
    }
    let identity = record.model_identity();
    let weight_bank_count = identity.weight_bank_count().map_err(|_| {
        ModelBankFieldStreamError::Sink(BlsDoryFixedModelStreamError::InvalidIdentity)
    })?;
    let sink = BlsDoryPreparedFixedModelV5Sink::new(
        record.manifest(),
        identity,
        record.record_digest(),
        record.model_identity_digest(),
        setup,
        scratch_directory,
    )
    .map_err(ModelBankFieldStreamError::Sink)?;
    verify_model_bank_into_staged_field_layout_sink(
        reader,
        record.manifest(),
        identity.layers_per_bank(),
        weight_bank_count,
        sink,
    )
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BlsDoryFixedModelStreamError {
    #[error("the streamed fixed-model setup or padded geometry is invalid")]
    InvalidGeometry,
    #[error("the streamed fixed-model chunk order, offset, or length is invalid")]
    InvalidChunk,
    #[error("the streamed fixed-model field value is not a centered model byte")]
    InvalidFieldValue,
    #[error("the verified model-bank receipt does not match the requested identity")]
    ReceiptMismatch,
    #[error("the authenticated fixed-model commitments do not form a valid identity")]
    InvalidIdentity,
    #[error("the authenticated fixed-model commitment does not match Dory V3 role {role}")]
    DoryV3CommitmentMismatch { role: u32 },
    #[error("authenticated fixed-model prover storage failed")]
    ProverStorage,
}

struct PreparedDoryRole<'a> {
    role: ModelPcsRole,
    expected_elements: u64,
    next_offset: u64,
    writer: PreparedDoryWriter<'a>,
}

enum PreparedDoryWriter<'a> {
    Scalar(BlsDoryCommittedPolynomialWriter<'a>),
    SignedByte(BlsDoryCommittedPolynomialWriter<'a>),
}

struct BlsDoryPreparedFixedModelSink<'a> {
    expected_model: ModelPcsIdentity,
    setup: &'a DeterministicBlsDorySetup,
    roles: Vec<PreparedDoryRole<'a>>,
    next_role: usize,
}

impl<'a> BlsDoryPreparedFixedModelSink<'a> {
    fn new(
        trusted_model: &ModelPcsIdentity,
        padded_variables: usize,
        setup: &'a DeterministicBlsDorySetup,
        scratch_directory: &Path,
    ) -> Result<Self, BlsDoryFixedModelStreamError> {
        trusted_model
            .validate()
            .map_err(|_| BlsDoryFixedModelStreamError::InvalidIdentity)?;
        setup
            .validate()
            .map_err(|_| BlsDoryFixedModelStreamError::InvalidGeometry)?;
        if padded_variables == 0 || padded_variables > setup.max_log_n() {
            return Err(BlsDoryFixedModelStreamError::InvalidGeometry);
        }
        let padded_elements = 1_u64
            .checked_shl(padded_variables as u32)
            .ok_or(BlsDoryFixedModelStreamError::InvalidGeometry)?;
        let base_elements = u64::from(trusted_model.batch)
            .checked_mul(u64::from(trusted_model.dimension))
            .ok_or(BlsDoryFixedModelStreamError::InvalidGeometry)?;
        let weight_elements = u64::from(trusted_model.layers_per_bank)
            .checked_mul(u64::from(trusted_model.dimension))
            .and_then(|value| value.checked_mul(u64::from(trusted_model.dimension)))
            .ok_or(BlsDoryFixedModelStreamError::InvalidGeometry)?;
        if !base_elements.is_power_of_two()
            || !weight_elements.is_power_of_two()
            || base_elements > padded_elements
            || weight_elements > padded_elements
        {
            return Err(BlsDoryFixedModelStreamError::InvalidGeometry);
        }
        let nu = padded_variables / 2;
        let sigma = padded_variables - nu;
        let mut role_specs = Vec::with_capacity(1 + trusted_model.weight_bank_commitments.len());
        role_specs.push((ModelPcsRole::BaseInput, base_elements));
        for index in 0..trusted_model.weight_bank_commitments.len() {
            role_specs.push((
                ModelPcsRole::WeightBank {
                    index: u32::try_from(index)
                        .map_err(|_| BlsDoryFixedModelStreamError::InvalidGeometry)?,
                },
                weight_elements,
            ));
        }
        let roles = role_specs
            .into_iter()
            .map(|(role, expected_elements)| {
                let explicit_count = usize::try_from(expected_elements)
                    .map_err(|_| BlsDoryFixedModelStreamError::InvalidGeometry)?;
                let writer = match role {
                    ModelPcsRole::BaseInput => PreparedDoryWriter::Scalar(
                        BlsDoryCommittedPolynomialWriter::create(
                            scratch_directory,
                            explicit_count,
                            nu,
                            sigma,
                            setup,
                        )
                        .map_err(|_| BlsDoryFixedModelStreamError::ProverStorage)?,
                    ),
                    ModelPcsRole::WeightBank { .. } => PreparedDoryWriter::SignedByte(
                        BlsDoryCommittedPolynomialWriter::create_signed_byte(
                            scratch_directory,
                            explicit_count,
                            nu,
                            sigma,
                            125,
                            setup,
                        )
                        .map_err(|_| BlsDoryFixedModelStreamError::ProverStorage)?,
                    ),
                };
                Ok(PreparedDoryRole {
                    role,
                    expected_elements,
                    next_offset: 0,
                    writer,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            expected_model: trusted_model.clone(),
            setup,
            roles,
            next_role: 0,
        })
    }
}

impl StagedModelFieldSink for BlsDoryPreparedFixedModelSink<'_> {
    type Error = BlsDoryFixedModelStreamError;
    type Output = BlsDoryPreparedFixedModel;

    fn write_chunk(&mut self, chunk: ModelFieldChunk<'_>) -> Result<(), Self::Error> {
        let role = self
            .roles
            .get_mut(self.next_role)
            .ok_or(BlsDoryFixedModelStreamError::InvalidChunk)?;
        let chunk_len = u64::try_from(chunk.elements.len())
            .map_err(|_| BlsDoryFixedModelStreamError::InvalidChunk)?;
        let chunk_end = chunk
            .role_offset
            .checked_add(chunk_len)
            .ok_or(BlsDoryFixedModelStreamError::InvalidChunk)?;
        if chunk.elements.is_empty()
            || chunk.role != role.role
            || chunk.role_elements != role.expected_elements
            || chunk.role_offset != role.next_offset
            || chunk_end > role.expected_elements
        {
            return Err(BlsDoryFixedModelStreamError::InvalidChunk);
        }
        match &mut role.writer {
            PreparedDoryWriter::Scalar(writer) => {
                let scalars = chunk
                    .elements
                    .iter()
                    .copied()
                    .map(bls_scalar_from_model_field)
                    .collect::<Result<Vec<_>, _>>()?;
                writer
                    .write_scalars(&scalars)
                    .map_err(|_| BlsDoryFixedModelStreamError::ProverStorage)?;
            }
            PreparedDoryWriter::SignedByte(writer) => {
                let values = chunk
                    .elements
                    .iter()
                    .copied()
                    .map(signed_model_value)
                    .collect::<Result<Vec<_>, _>>()?;
                writer
                    .write_signed_values(&values)
                    .map_err(|_| BlsDoryFixedModelStreamError::ProverStorage)?;
            }
        }
        role.next_offset = chunk_end;
        if chunk_end == role.expected_elements {
            self.next_role += 1;
        }
        Ok(())
    }

    fn finish_verified(
        self,
        receipt: VerifiedModelBankReceipt,
    ) -> Result<Self::Output, Self::Error> {
        if self.next_role != self.roles.len()
            || receipt.identity() != &self.expected_model
            || usize::try_from(receipt.layout().weight_bank_count()).ok()
                != Some(self.expected_model.weight_bank_commitments.len())
            || receipt.layout().layers_per_bank() != self.expected_model.layers_per_bank
            || self
                .roles
                .iter()
                .any(|role| role.next_offset != role.expected_elements)
        {
            return Err(BlsDoryFixedModelStreamError::ReceiptMismatch);
        }
        let mut polynomials = self.roles.into_iter().map(|role| {
            match role.writer {
                PreparedDoryWriter::Scalar(writer) | PreparedDoryWriter::SignedByte(writer) => {
                    writer.finish()
                }
            }
            .map_err(|_| BlsDoryFixedModelStreamError::ProverStorage)
        });
        let base_input = polynomials
            .next()
            .ok_or(BlsDoryFixedModelStreamError::InvalidIdentity)??;
        let weight_banks = polynomials.collect::<Result<Vec<_>, _>>()?;
        let identity = BlsDoryFixedModelIdentity {
            protocol_version: BLS_DORY_FIXED_MODEL_IDENTITY_VERSION,
            model_pcs_identity_digest: self
                .expected_model
                .digest()
                .map_err(|_| BlsDoryFixedModelStreamError::InvalidIdentity)?,
            setup_identity: self.setup.identity(),
            base_input_commitment: base_input.commitment(),
            weight_bank_commitments: weight_banks
                .iter()
                .map(BlsDoryCommittedPolynomial::commitment)
                .collect(),
        };
        identity
            .validate(
                &self.expected_model,
                self.expected_model.weight_bank_commitments.len(),
                self.setup,
            )
            .map_err(|_| BlsDoryFixedModelStreamError::InvalidIdentity)?;
        Ok(BlsDoryPreparedFixedModel {
            identity,
            base_input,
            weight_banks,
        })
    }
}

struct BlsDoryPreparedFixedModelV5Sink<'a> {
    expected_manifest: ModelBankManifest,
    record_digest: Digest32,
    model_identity_digest: Digest32,
    model_identity: DoryV3ModelIdentityV1,
    roles: Vec<PreparedDoryRole<'a>>,
    next_role: usize,
}

impl<'a> BlsDoryPreparedFixedModelV5Sink<'a> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        expected_manifest: &ModelBankManifest,
        model_identity: &DoryV3ModelIdentityV1,
        record_digest: Digest32,
        model_identity_digest: Digest32,
        setup: &'a DeterministicBlsDorySetup,
        scratch_directory: &Path,
    ) -> Result<Self, BlsDoryFixedModelStreamError> {
        model_identity
            .validate()
            .map_err(|_| BlsDoryFixedModelStreamError::InvalidIdentity)?;
        model_identity
            .verify_manifest(expected_manifest)
            .map_err(|_| BlsDoryFixedModelStreamError::InvalidIdentity)?;
        if model_identity_digest.into_bytes()
            != model_identity
                .digest()
                .map_err(|_| BlsDoryFixedModelStreamError::InvalidIdentity)?
        {
            return Err(BlsDoryFixedModelStreamError::InvalidIdentity);
        }
        setup
            .validate()
            .map_err(|_| BlsDoryFixedModelStreamError::InvalidGeometry)?;
        let padded_variables = usize::try_from(model_identity.padded_variables())
            .map_err(|_| BlsDoryFixedModelStreamError::InvalidGeometry)?;
        if padded_variables == 0
            || padded_variables != setup.max_log_n()
            || model_identity.setup_identity() != setup.identity()
        {
            return Err(BlsDoryFixedModelStreamError::InvalidGeometry);
        }
        let padded_elements = 1_u64
            .checked_shl(model_identity.padded_variables())
            .ok_or(BlsDoryFixedModelStreamError::InvalidGeometry)?;
        let base_elements = u64::from(model_identity.batch())
            .checked_mul(u64::from(model_identity.dimension()))
            .ok_or(BlsDoryFixedModelStreamError::InvalidGeometry)?;
        let weight_elements = u64::from(model_identity.layers_per_bank())
            .checked_mul(u64::from(model_identity.dimension()))
            .and_then(|value| value.checked_mul(u64::from(model_identity.dimension())))
            .ok_or(BlsDoryFixedModelStreamError::InvalidGeometry)?;
        if !base_elements.is_power_of_two()
            || !weight_elements.is_power_of_two()
            || base_elements > padded_elements
            || weight_elements > padded_elements
        {
            return Err(BlsDoryFixedModelStreamError::InvalidGeometry);
        }

        let weight_bank_count = model_identity
            .weight_bank_count()
            .map_err(|_| BlsDoryFixedModelStreamError::InvalidGeometry)?;
        let role_capacity = usize::try_from(weight_bank_count)
            .ok()
            .and_then(|count| count.checked_add(1))
            .ok_or(BlsDoryFixedModelStreamError::InvalidGeometry)?;
        let mut role_specs = Vec::with_capacity(role_capacity);
        role_specs.push((ModelPcsRole::BaseInput, base_elements));
        for index in 0..weight_bank_count {
            role_specs.push((ModelPcsRole::WeightBank { index }, weight_elements));
        }
        let nu = padded_variables / 2;
        let sigma = padded_variables - nu;
        let roles = role_specs
            .into_iter()
            .map(|(role, expected_elements)| {
                let explicit_count = usize::try_from(expected_elements)
                    .map_err(|_| BlsDoryFixedModelStreamError::InvalidGeometry)?;
                let writer = match role {
                    ModelPcsRole::BaseInput => PreparedDoryWriter::Scalar(
                        BlsDoryCommittedPolynomialWriter::create(
                            scratch_directory,
                            explicit_count,
                            nu,
                            sigma,
                            setup,
                        )
                        .map_err(|_| BlsDoryFixedModelStreamError::ProverStorage)?,
                    ),
                    ModelPcsRole::WeightBank { .. } => PreparedDoryWriter::SignedByte(
                        BlsDoryCommittedPolynomialWriter::create_signed_byte(
                            scratch_directory,
                            explicit_count,
                            nu,
                            sigma,
                            125,
                            setup,
                        )
                        .map_err(|_| BlsDoryFixedModelStreamError::ProverStorage)?,
                    ),
                };
                Ok(PreparedDoryRole {
                    role,
                    expected_elements,
                    next_offset: 0,
                    writer,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            expected_manifest: *expected_manifest,
            record_digest,
            model_identity_digest,
            model_identity: model_identity.clone(),
            roles,
            next_role: 0,
        })
    }
}

impl StagedModelFieldLayoutSink for BlsDoryPreparedFixedModelV5Sink<'_> {
    type Error = BlsDoryFixedModelStreamError;
    type Output = BlsDoryPreparedFixedModelV5;

    fn write_chunk(&mut self, chunk: ModelFieldChunk<'_>) -> Result<(), Self::Error> {
        let role = self
            .roles
            .get_mut(self.next_role)
            .ok_or(BlsDoryFixedModelStreamError::InvalidChunk)?;
        let chunk_len = u64::try_from(chunk.elements.len())
            .map_err(|_| BlsDoryFixedModelStreamError::InvalidChunk)?;
        let chunk_end = chunk
            .role_offset
            .checked_add(chunk_len)
            .ok_or(BlsDoryFixedModelStreamError::InvalidChunk)?;
        if chunk.elements.is_empty()
            || chunk.role != role.role
            || chunk.role_elements != role.expected_elements
            || chunk.role_offset != role.next_offset
            || chunk_end > role.expected_elements
        {
            return Err(BlsDoryFixedModelStreamError::InvalidChunk);
        }
        match &mut role.writer {
            PreparedDoryWriter::Scalar(writer) => {
                let scalars = chunk
                    .elements
                    .iter()
                    .copied()
                    .map(bls_scalar_from_model_field)
                    .collect::<Result<Vec<_>, _>>()?;
                writer
                    .write_scalars(&scalars)
                    .map_err(|_| BlsDoryFixedModelStreamError::ProverStorage)?;
            }
            PreparedDoryWriter::SignedByte(writer) => {
                let values = chunk
                    .elements
                    .iter()
                    .copied()
                    .map(signed_model_value)
                    .collect::<Result<Vec<_>, _>>()?;
                writer
                    .write_signed_values(&values)
                    .map_err(|_| BlsDoryFixedModelStreamError::ProverStorage)?;
            }
        }
        role.next_offset = chunk_end;
        if chunk_end == role.expected_elements {
            self.next_role += 1;
        }
        Ok(())
    }

    fn finish_verified(
        self,
        receipt: VerifiedModelBankLayoutReceipt,
    ) -> Result<Self::Output, Self::Error> {
        let expected_weight_count = self
            .model_identity
            .weight_bank_count()
            .map_err(|_| BlsDoryFixedModelStreamError::InvalidIdentity)?;
        if self.next_role != self.roles.len()
            || receipt.manifest() != &self.expected_manifest
            || receipt.layout().layers_per_bank() != self.model_identity.layers_per_bank()
            || receipt.layout().weight_bank_count() != expected_weight_count
            || self
                .roles
                .iter()
                .any(|role| role.next_offset != role.expected_elements)
        {
            return Err(BlsDoryFixedModelStreamError::ReceiptMismatch);
        }

        let mut polynomials = self.roles.into_iter().map(|role| {
            match role.writer {
                PreparedDoryWriter::Scalar(writer) | PreparedDoryWriter::SignedByte(writer) => {
                    writer.finish()
                }
            }
            .map_err(|_| BlsDoryFixedModelStreamError::ProverStorage)
        });
        let base_input = polynomials
            .next()
            .ok_or(BlsDoryFixedModelStreamError::InvalidIdentity)??;
        let weight_banks = polynomials.collect::<Result<Vec<_>, _>>()?;
        if base_input.commitment() != self.model_identity.base_input_commitment() {
            return Err(BlsDoryFixedModelStreamError::DoryV3CommitmentMismatch { role: 0 });
        }
        let expected_weights = self.model_identity.weight_bank_commitments();
        if weight_banks.len() != expected_weights.len() {
            return Err(BlsDoryFixedModelStreamError::InvalidIdentity);
        }
        for (index, (actual, expected)) in
            weight_banks.iter().zip(expected_weights.iter()).enumerate()
        {
            if actual.commitment() != *expected {
                let role = u32::try_from(index + 1)
                    .map_err(|_| BlsDoryFixedModelStreamError::InvalidIdentity)?;
                return Err(BlsDoryFixedModelStreamError::DoryV3CommitmentMismatch { role });
            }
        }

        Ok(BlsDoryPreparedFixedModelV5 {
            record_digest: self.record_digest,
            model_identity_digest: self.model_identity_digest,
            model_identity: self.model_identity,
            base_input,
            weight_banks,
        })
    }
}

struct StreamedDoryRole {
    role: ModelPcsRole,
    expected_elements: u64,
    next_offset: u64,
    row_index: usize,
    column_offset: usize,
    row_commitment: BlsDoryG1,
    commitment: BlsDoryGt,
}

impl StreamedDoryRole {
    fn new(role: ModelPcsRole, expected_elements: u64) -> Self {
        Self {
            role,
            expected_elements,
            next_offset: 0,
            row_index: 0,
            column_offset: 0,
            row_commitment: BlsDoryG1::identity(),
            commitment: BlsDoryGt::identity(),
        }
    }

    fn write(
        &mut self,
        elements: &[u64],
        columns: usize,
        rows: usize,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<(), BlsDoryFixedModelStreamError> {
        let mut remaining = elements;
        while !remaining.is_empty() {
            if self.row_index >= rows {
                return Err(BlsDoryFixedModelStreamError::InvalidChunk);
            }
            let take = remaining.len().min(columns - self.column_offset);
            let scalars = remaining[..take]
                .iter()
                .copied()
                .map(bls_scalar_from_model_field)
                .collect::<Result<Vec<_>, _>>()?;
            let partial = setup
                .commit_row_segment(self.column_offset, &scalars)
                .map_err(|_| BlsDoryFixedModelStreamError::InvalidGeometry)?;
            self.row_commitment = self.row_commitment + partial;
            self.column_offset += take;
            remaining = &remaining[take..];

            if self.column_offset == columns {
                self.commitment = self.commitment
                    + setup
                        .pair_committed_row(self.row_index, &self.row_commitment)
                        .map_err(|_| BlsDoryFixedModelStreamError::InvalidGeometry)?;
                self.row_index += 1;
                self.column_offset = 0;
                self.row_commitment = BlsDoryG1::identity();
            }
        }
        Ok(())
    }

    fn finish(
        mut self,
        rows: usize,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<BlsDoryGt, BlsDoryFixedModelStreamError> {
        if self.next_offset != self.expected_elements || self.row_index > rows {
            return Err(BlsDoryFixedModelStreamError::InvalidChunk);
        }
        if self.column_offset != 0 {
            if self.row_index >= rows {
                return Err(BlsDoryFixedModelStreamError::InvalidChunk);
            }
            self.commitment = self.commitment
                + setup
                    .pair_committed_row(self.row_index, &self.row_commitment)
                    .map_err(|_| BlsDoryFixedModelStreamError::InvalidGeometry)?;
        }
        Ok(self.commitment)
    }
}

struct BlsDoryModelLayoutSink<'a> {
    expected_manifest: ModelBankManifest,
    layers_per_bank: u32,
    weight_bank_count: u32,
    setup: &'a DeterministicBlsDorySetup,
    columns: usize,
    rows: usize,
    roles: Vec<StreamedDoryRole>,
    next_role: usize,
}

impl<'a> BlsDoryModelLayoutSink<'a> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        expected_manifest: &ModelBankManifest,
        batch: u32,
        dimension: u32,
        layers_per_bank: u32,
        weight_bank_count: u32,
        padded_variables: usize,
        setup: &'a DeterministicBlsDorySetup,
    ) -> Result<Self, BlsDoryFixedModelStreamError> {
        setup
            .validate()
            .map_err(|_| BlsDoryFixedModelStreamError::InvalidGeometry)?;
        expected_manifest
            .digest()
            .map_err(|_| BlsDoryFixedModelStreamError::InvalidIdentity)?;
        if batch == 0
            || dimension == 0
            || layers_per_bank == 0
            || weight_bank_count == 0
            || !batch.is_power_of_two()
            || !dimension.is_power_of_two()
            || !layers_per_bank.is_power_of_two()
            || padded_variables == 0
            || padded_variables > setup.max_log_n()
        {
            return Err(BlsDoryFixedModelStreamError::InvalidGeometry);
        }
        let expected_layers = layers_per_bank
            .checked_mul(weight_bank_count)
            .ok_or(BlsDoryFixedModelStreamError::InvalidGeometry)?;
        if expected_manifest.batch != batch
            || expected_manifest.dimension != dimension
            || expected_manifest.layers != expected_layers
        {
            return Err(BlsDoryFixedModelStreamError::InvalidIdentity);
        }

        let padded_elements = 1_u64
            .checked_shl(padded_variables as u32)
            .ok_or(BlsDoryFixedModelStreamError::InvalidGeometry)?;
        let nu = padded_variables / 2;
        let sigma = padded_variables - nu;
        let rows = 1_usize
            .checked_shl(nu as u32)
            .ok_or(BlsDoryFixedModelStreamError::InvalidGeometry)?;
        let columns = 1_usize
            .checked_shl(sigma as u32)
            .ok_or(BlsDoryFixedModelStreamError::InvalidGeometry)?;
        let base_elements = u64::from(batch)
            .checked_mul(u64::from(dimension))
            .ok_or(BlsDoryFixedModelStreamError::InvalidGeometry)?;
        let weight_elements = u64::from(layers_per_bank)
            .checked_mul(u64::from(dimension))
            .and_then(|value| value.checked_mul(u64::from(dimension)))
            .ok_or(BlsDoryFixedModelStreamError::InvalidGeometry)?;
        if !base_elements.is_power_of_two()
            || !weight_elements.is_power_of_two()
            || base_elements > padded_elements
            || weight_elements > padded_elements
        {
            return Err(BlsDoryFixedModelStreamError::InvalidGeometry);
        }

        let role_capacity = usize::try_from(weight_bank_count)
            .ok()
            .and_then(|count| count.checked_add(1))
            .ok_or(BlsDoryFixedModelStreamError::InvalidGeometry)?;
        let mut roles = Vec::with_capacity(role_capacity);
        roles.push(StreamedDoryRole::new(
            ModelPcsRole::BaseInput,
            base_elements,
        ));
        for index in 0..weight_bank_count {
            roles.push(StreamedDoryRole::new(
                ModelPcsRole::WeightBank { index },
                weight_elements,
            ));
        }

        Ok(Self {
            expected_manifest: *expected_manifest,
            layers_per_bank,
            weight_bank_count,
            setup,
            columns,
            rows,
            roles,
            next_role: 0,
        })
    }
}

impl StagedModelFieldLayoutSink for BlsDoryModelLayoutSink<'_> {
    type Error = BlsDoryFixedModelStreamError;
    type Output = BlsDoryDerivedModelCommitments;

    fn write_chunk(&mut self, chunk: ModelFieldChunk<'_>) -> Result<(), Self::Error> {
        let role = self
            .roles
            .get_mut(self.next_role)
            .ok_or(BlsDoryFixedModelStreamError::InvalidChunk)?;
        let chunk_len = u64::try_from(chunk.elements.len())
            .map_err(|_| BlsDoryFixedModelStreamError::InvalidChunk)?;
        let chunk_end = chunk
            .role_offset
            .checked_add(chunk_len)
            .ok_or(BlsDoryFixedModelStreamError::InvalidChunk)?;
        if chunk.elements.is_empty()
            || chunk.role != role.role
            || chunk.role_elements != role.expected_elements
            || chunk.role_offset != role.next_offset
            || chunk_end > role.expected_elements
        {
            return Err(BlsDoryFixedModelStreamError::InvalidChunk);
        }
        role.write(chunk.elements, self.columns, self.rows, self.setup)?;
        role.next_offset = chunk_end;
        if chunk_end == role.expected_elements {
            self.next_role += 1;
        }
        Ok(())
    }

    fn finish_verified(
        self,
        receipt: VerifiedModelBankLayoutReceipt,
    ) -> Result<Self::Output, Self::Error> {
        if self.next_role != self.roles.len()
            || receipt.manifest() != &self.expected_manifest
            || receipt.layout().layers_per_bank() != self.layers_per_bank
            || receipt.layout().weight_bank_count() != self.weight_bank_count
        {
            return Err(BlsDoryFixedModelStreamError::ReceiptMismatch);
        }
        let mut commitments = self
            .roles
            .into_iter()
            .map(|role| role.finish(self.rows, self.setup));
        let base_input = commitments
            .next()
            .ok_or(BlsDoryFixedModelStreamError::InvalidIdentity)??;
        let weight_banks = commitments.collect::<Result<Vec<_>, _>>()?;
        if u32::try_from(weight_banks.len()).ok() != Some(self.weight_bank_count) {
            return Err(BlsDoryFixedModelStreamError::InvalidIdentity);
        }
        Ok(BlsDoryDerivedModelCommitments {
            base_input,
            weight_banks,
        })
    }
}

struct BlsDoryFixedModelSink<'a> {
    expected_model: ModelPcsIdentity,
    setup: &'a DeterministicBlsDorySetup,
    columns: usize,
    rows: usize,
    roles: Vec<StreamedDoryRole>,
    next_role: usize,
}

impl<'a> BlsDoryFixedModelSink<'a> {
    fn new(
        trusted_model: &ModelPcsIdentity,
        padded_variables: usize,
        setup: &'a DeterministicBlsDorySetup,
    ) -> Result<Self, BlsDoryFixedModelStreamError> {
        trusted_model
            .validate()
            .map_err(|_| BlsDoryFixedModelStreamError::InvalidIdentity)?;
        setup
            .validate()
            .map_err(|_| BlsDoryFixedModelStreamError::InvalidGeometry)?;
        if padded_variables == 0 || padded_variables > setup.max_log_n() {
            return Err(BlsDoryFixedModelStreamError::InvalidGeometry);
        }
        let padded_elements = 1_u64
            .checked_shl(padded_variables as u32)
            .ok_or(BlsDoryFixedModelStreamError::InvalidGeometry)?;
        let nu = padded_variables / 2;
        let sigma = padded_variables - nu;
        let rows = 1_usize
            .checked_shl(nu as u32)
            .ok_or(BlsDoryFixedModelStreamError::InvalidGeometry)?;
        let columns = 1_usize
            .checked_shl(sigma as u32)
            .ok_or(BlsDoryFixedModelStreamError::InvalidGeometry)?;
        let base_elements = u64::from(trusted_model.batch)
            .checked_mul(u64::from(trusted_model.dimension))
            .ok_or(BlsDoryFixedModelStreamError::InvalidGeometry)?;
        let weight_elements = u64::from(trusted_model.layers_per_bank)
            .checked_mul(u64::from(trusted_model.dimension))
            .and_then(|value| value.checked_mul(u64::from(trusted_model.dimension)))
            .ok_or(BlsDoryFixedModelStreamError::InvalidGeometry)?;
        if !base_elements.is_power_of_two()
            || !weight_elements.is_power_of_two()
            || base_elements > padded_elements
            || weight_elements > padded_elements
        {
            return Err(BlsDoryFixedModelStreamError::InvalidGeometry);
        }

        let mut roles = Vec::with_capacity(1 + trusted_model.weight_bank_commitments.len());
        roles.push(StreamedDoryRole::new(
            ModelPcsRole::BaseInput,
            base_elements,
        ));
        roles.extend(
            trusted_model
                .weight_bank_commitments
                .iter()
                .enumerate()
                .map(|(index, _)| {
                    let index = u32::try_from(index)
                        .map_err(|_| BlsDoryFixedModelStreamError::InvalidGeometry)?;
                    Ok(StreamedDoryRole::new(
                        ModelPcsRole::WeightBank { index },
                        weight_elements,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?,
        );
        Ok(Self {
            expected_model: trusted_model.clone(),
            setup,
            columns,
            rows,
            roles,
            next_role: 0,
        })
    }
}

impl StagedModelFieldSink for BlsDoryFixedModelSink<'_> {
    type Error = BlsDoryFixedModelStreamError;
    type Output = BlsDoryFixedModelIdentity;

    fn write_chunk(&mut self, chunk: ModelFieldChunk<'_>) -> Result<(), Self::Error> {
        let role = self
            .roles
            .get_mut(self.next_role)
            .ok_or(BlsDoryFixedModelStreamError::InvalidChunk)?;
        let chunk_len = u64::try_from(chunk.elements.len())
            .map_err(|_| BlsDoryFixedModelStreamError::InvalidChunk)?;
        let chunk_end = chunk
            .role_offset
            .checked_add(chunk_len)
            .ok_or(BlsDoryFixedModelStreamError::InvalidChunk)?;
        if chunk.elements.is_empty()
            || chunk.role != role.role
            || chunk.role_elements != role.expected_elements
            || chunk.role_offset != role.next_offset
            || chunk_end > role.expected_elements
        {
            return Err(BlsDoryFixedModelStreamError::InvalidChunk);
        }
        role.write(chunk.elements, self.columns, self.rows, self.setup)?;
        role.next_offset = chunk_end;
        if chunk_end == role.expected_elements {
            self.next_role += 1;
        }
        Ok(())
    }

    fn finish_verified(
        self,
        receipt: VerifiedModelBankReceipt,
    ) -> Result<Self::Output, Self::Error> {
        if self.next_role != self.roles.len()
            || receipt.identity() != &self.expected_model
            || usize::try_from(receipt.layout().weight_bank_count()).ok()
                != Some(self.expected_model.weight_bank_commitments.len())
            || receipt.layout().layers_per_bank() != self.expected_model.layers_per_bank
        {
            return Err(BlsDoryFixedModelStreamError::ReceiptMismatch);
        }
        let mut commitments = self
            .roles
            .into_iter()
            .map(|role| role.finish(self.rows, self.setup));
        let base_input_commitment = commitments
            .next()
            .ok_or(BlsDoryFixedModelStreamError::InvalidIdentity)??;
        let weight_bank_commitments = commitments.collect::<Result<Vec<_>, _>>()?;
        let identity = BlsDoryFixedModelIdentity {
            protocol_version: BLS_DORY_FIXED_MODEL_IDENTITY_VERSION,
            model_pcs_identity_digest: self
                .expected_model
                .digest()
                .map_err(|_| BlsDoryFixedModelStreamError::InvalidIdentity)?,
            setup_identity: self.setup.identity(),
            base_input_commitment,
            weight_bank_commitments,
        };
        identity
            .validate(
                &self.expected_model,
                self.expected_model.weight_bank_commitments.len(),
                self.setup,
            )
            .map_err(|_| BlsDoryFixedModelStreamError::InvalidIdentity)?;
        Ok(identity)
    }
}

fn bls_scalar_from_model_field(value: u64) -> Result<BlsDoryFr, BlsDoryFixedModelStreamError> {
    signed_model_value(value).map(BlsDoryFr::from_i64)
}

pub(crate) fn signed_model_value(value: u64) -> Result<i64, BlsDoryFixedModelStreamError> {
    if value <= 125 {
        return i64::try_from(value).map_err(|_| BlsDoryFixedModelStreamError::InvalidFieldValue);
    }
    let negative_floor = GOLDILOCKS_MODULUS - 125;
    if value < negative_floor || value >= GOLDILOCKS_MODULUS {
        return Err(BlsDoryFixedModelStreamError::InvalidFieldValue);
    }
    i64::try_from(GOLDILOCKS_MODULUS - value)
        .map(|magnitude| -magnitude)
        .map_err(|_| BlsDoryFixedModelStreamError::InvalidFieldValue)
}

fn commit_fixed_table(
    values: &[i64],
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryCommittedPolynomial, BlsDorySharedLayoutError> {
    commit_fixed_table_with_optional_scratch(values, padded_variables, setup, None)
}

struct PaddedFixedRowSource<'a> {
    values: &'a [i64],
    rows: usize,
    columns: usize,
}

impl BlsDoryRowSource for PaddedFixedRowSource<'_> {
    type Error = std::convert::Infallible;

    fn rows(&self) -> usize {
        self.rows
    }

    fn columns(&self) -> usize {
        self.columns
    }

    fn explicit_scalar_count(&self) -> usize {
        self.values.len()
    }

    fn read_row(
        &mut self,
        row_index: usize,
        output: &mut [BlsDoryFr],
    ) -> Result<usize, Self::Error> {
        let start = row_index * self.columns;
        for (column, scalar) in output.iter_mut().enumerate() {
            *scalar = self
                .values
                .get(start + column)
                .copied()
                .map(BlsDoryFr::from_i64)
                .unwrap_or_else(BlsDoryFr::zero);
        }
        Ok(output.len())
    }
}

fn commit_fixed_table_with_optional_scratch(
    values: &[i64],
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: Option<&Path>,
) -> Result<BlsDoryCommittedPolynomial, BlsDorySharedLayoutError> {
    let padded_len = 1usize
        .checked_shl(padded_variables as u32)
        .ok_or(BlsDorySharedLayoutError::FixedModelIdentity)?;
    if values.is_empty() || values.len() > padded_len || !values.len().is_power_of_two() {
        return Err(BlsDorySharedLayoutError::FixedModelIdentity);
    }
    let nu = padded_variables / 2;
    let sigma = padded_variables - nu;
    if let Some(scratch_directory) = scratch_directory {
        let rows = 1usize
            .checked_shl(nu as u32)
            .ok_or(BlsDorySharedLayoutError::FixedModelIdentity)?;
        let columns = 1usize
            .checked_shl(sigma as u32)
            .ok_or(BlsDorySharedLayoutError::FixedModelIdentity)?;
        let mut source = PaddedFixedRowSource {
            values,
            rows,
            columns,
        };
        return commit_bls_dory_row_source_with_scratch(
            &mut source,
            nu,
            sigma,
            setup,
            scratch_directory,
        )
        .map_err(Into::into);
    }
    let mut coefficients = values
        .iter()
        .copied()
        .map(BlsDoryFr::from_i64)
        .collect::<Vec<_>>();
    coefficients.resize(padded_len, BlsDoryFr::zero());
    commit_bls_dory_polynomial(coefficients, nu, sigma, setup).map_err(Into::into)
}

/// Arithmetic and range proofs that share the exact packed transition commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsDoryTransitionRangeProof {
    pub arithmetic: BlsDoryTransitionProof,
    pub range: BlsDoryRangeLogUpProof,
}

/// One or more matrix and transition checkpoints plus wiring, authenticated by
/// one shared Dory opening payload. The production shape uses three matrix
/// proofs and four transition/range proofs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsDorySharedLayoutProof {
    pub protocol_version: u16,
    pub padded_variables: u16,
    pub matrices: Vec<BlsDoryMatrixProof>,
    pub transitions: Vec<BlsDoryTransitionRangeProof>,
    pub wiring: BlsDoryWiringProof,
    pub link_evaluations: Vec<BlsDoryFr>,
    /// Signed final-activation MLE at the bridge point derived after all
    /// component commitments and transcript messages are fixed.
    pub final_output_evaluation: BlsDoryFr,
    pub opening_proof: Vec<u8>,
}

/// Canonical authenticated Layout V5 proof and the validated V3 context used
/// to interpret it.
///
/// The inner wire grammar deliberately reuses the frozen shared-layout magic,
/// while protocol version 5 is a hard downgrade barrier. Construction outside
/// this module is possible only through [`Self::decode_with_context`], which
/// requires the typed context derived from a bank-authenticated Record V2.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsDorySharedLayoutV5Proof {
    context: BlsDorySharedLayoutV5Context,
    proof: BlsDorySharedLayoutProof,
}

/// Verifier-authenticated Dory side of the cross-field final-output bridge.
///
/// The BLAKE3 argument must prove that its private bytes, shifted down by 125,
/// have this exact BLS12-381 scalar-field evaluation at `cell_point`.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBlsDoryFinalOutputOpening {
    cell_point: Vec<BlsDoryFr>,
    signed_evaluation: BlsDoryFr,
    transcript_binding: [u8; 32],
}

impl VerifiedBlsDoryFinalOutputOpening {
    pub fn cell_point(&self) -> &[BlsDoryFr] {
        &self.cell_point
    }

    pub const fn signed_evaluation(&self) -> BlsDoryFr {
        self.signed_evaluation
    }

    pub const fn transcript_binding(&self) -> [u8; 32] {
        self.transcript_binding
    }
}

/// Final-output data derived from authenticated component transcripts but not
/// yet authorized by their aggregate opening proof.
pub(crate) struct PendingBlsDoryFinalOutputOpening {
    cell_point: Vec<BlsDoryFr>,
    signed_evaluation: BlsDoryFr,
    transcript_binding: [u8; 32],
}

#[allow(dead_code)]
impl PendingBlsDoryFinalOutputOpening {
    fn into_verified(self) -> VerifiedBlsDoryFinalOutputOpening {
        VerifiedBlsDoryFinalOutputOpening {
            cell_point: self.cell_point,
            signed_evaluation: self.signed_evaluation,
            transcript_binding: self.transcript_binding,
        }
    }

    pub(crate) fn cell_point(&self) -> &[BlsDoryFr] {
        &self.cell_point
    }

    pub(crate) const fn signed_evaluation(&self) -> BlsDoryFr {
        self.signed_evaluation
    }

    pub(crate) const fn transcript_binding(&self) -> [u8; 32] {
        self.transcript_binding
    }
}

#[allow(dead_code)]
pub(crate) struct PreparedBlsDorySharedLayoutProverState {
    aggregate_layout: BlsDoryAggregateLayout,
    shared_opening_binding: [u8; 32],
    opening_sets: Vec<BlsDoryDeferredOpeningSet>,
    expected_claims: Vec<BlsDoryOpeningClaim>,
    proof: BlsDorySharedLayoutProof,
    #[cfg_attr(not(test), allow(dead_code))]
    pending_final_output: PendingBlsDoryFinalOutputOpening,
}

#[allow(dead_code)]
impl PreparedBlsDorySharedLayoutProverState {
    pub(crate) fn pending_final_output(&self) -> &PendingBlsDoryFinalOutputOpening {
        &self.pending_final_output
    }

    #[cfg(test)]
    pub(crate) const fn shared_opening_binding(&self) -> [u8; 32] {
        self.shared_opening_binding
    }
}

pub(crate) struct PreparedBlsDorySharedLayoutVerifierState {
    aggregate_layout: BlsDoryAggregateLayout,
    shared_opening_binding: [u8; 32],
    claims: Vec<BlsDoryOpeningClaim>,
    pending_final_output: PendingBlsDoryFinalOutputOpening,
}

#[allow(dead_code)]
impl PreparedBlsDorySharedLayoutVerifierState {
    pub(crate) fn pending_final_output(&self) -> &PendingBlsDoryFinalOutputOpening {
        &self.pending_final_output
    }

    #[cfg(test)]
    pub(crate) const fn shared_opening_binding(&self) -> [u8; 32] {
        self.shared_opening_binding
    }
}

/// Bank-authenticated Layout V5 prover state before its one aggregate opening
/// is produced. Every fixed polynomial is retained through an authenticated
/// [`BlsDoryPreparedFixedModelV5`] capability during preparation.
#[must_use]
#[allow(dead_code)]
pub struct PreparedBlsDorySharedLayoutV5ProverState {
    context: BlsDorySharedLayoutV5Context,
    aggregate_layout: BlsDoryAggregateLayout,
    shared_opening_binding: BlsDorySharedOpeningBindingV5,
    opening_sets: Vec<BlsDoryDeferredOpeningSet>,
    expected_claims: Vec<BlsDoryOpeningClaim>,
    proof: BlsDorySharedLayoutProof,
    pending_final_output: PendingBlsDoryFinalOutputOpening,
}

#[allow(dead_code)]
impl PreparedBlsDorySharedLayoutV5ProverState {
    pub const fn shared_opening_binding(&self) -> BlsDorySharedOpeningBindingV5 {
        self.shared_opening_binding
    }

    pub(crate) const fn pending_final_output(&self) -> &PendingBlsDoryFinalOutputOpening {
        &self.pending_final_output
    }

    #[cfg(test)]
    pub(crate) const fn proof_for_test(&self) -> &BlsDorySharedLayoutProof {
        &self.proof
    }

    #[cfg(test)]
    pub(crate) fn expected_claim_count_for_test(&self) -> usize {
        self.expected_claims.len()
    }
}

/// Bank-authenticated Layout V5 verifier state after every component
/// transcript has replayed but before its aggregate opening is accepted.
#[must_use]
#[allow(dead_code)]
pub struct PreparedBlsDorySharedLayoutV5VerifierState {
    context: BlsDorySharedLayoutV5Context,
    aggregate_layout: BlsDoryAggregateLayout,
    shared_opening_binding: BlsDorySharedOpeningBindingV5,
    claims: Vec<BlsDoryOpeningClaim>,
    opening_proof: Vec<u8>,
    pending_final_output: PendingBlsDoryFinalOutputOpening,
}

#[allow(dead_code)]
impl PreparedBlsDorySharedLayoutV5VerifierState {
    pub const fn shared_opening_binding(&self) -> BlsDorySharedOpeningBindingV5 {
        self.shared_opening_binding
    }

    pub(crate) const fn pending_final_output(&self) -> &PendingBlsDoryFinalOutputOpening {
        &self.pending_final_output
    }
}

/// Opaque six-opening capability produced by the native BLAKE3 prover for
/// Layout V5 composition. Its private fields prevent callers from supplying an
/// arbitrary untyped deferred-opening set to the public composer.
#[must_use]
#[allow(dead_code)]
struct BlsDorySharedLayoutV5NativeProverOpenings {
    openings: BlsDoryDeferredOpeningSet,
    opening_binding: [u8; 32],
}

#[allow(dead_code)]
impl BlsDorySharedLayoutV5NativeProverOpenings {
    fn from_deferred(
        openings: BlsDoryDeferredOpeningSet,
        opening_binding: [u8; 32],
    ) -> Result<Self, BlsDorySharedLayoutError> {
        if openings.claims().len() != BLS_DORY_SHARED_NATIVE_COMPOSITION_CLAIMS
            || opening_binding == [0; 32]
        {
            return Err(BlsDorySharedLayoutError::OpeningClaims);
        }
        Ok(Self {
            openings,
            opening_binding,
        })
    }
}

impl BlsDorySharedLayoutProof {
    /// Encode the component algebraic messages and their single shared opening
    /// payload with exact length-delimited canonical framing.
    pub fn encode(
        &self,
        matrix_statements: &[StructuredMatrixStatement],
        transition_statements: &[StructuredTransitionStatement],
        wiring_statement: StructuredWiringStatement,
    ) -> Result<Vec<u8>, BlsDorySharedLayoutError> {
        validate_shared_component_shape(self, usize::from(self.padded_variables))?;
        if self.matrices.len() != matrix_statements.len()
            || self.transitions.len() != transition_statements.len()
        {
            return Err(BlsDorySharedLayoutError::InvalidProofShape);
        }
        validate_shared_link_topology(matrix_statements, transition_statements, wiring_statement)?;
        let matrices = self
            .matrices
            .iter()
            .zip(matrix_statements)
            .map(|(proof, statement)| proof.encode_deferred(*statement))
            .collect::<Result<Vec<_>, _>>()?;
        let transitions = self
            .transitions
            .iter()
            .zip(transition_statements)
            .map(|(proof, statement)| {
                Ok((
                    proof.arithmetic.encode_deferred(*statement)?,
                    proof.range.encode_deferred(*statement)?,
                ))
            })
            .collect::<Result<Vec<_>, BlsDorySharedLayoutError>>()?;
        let wiring = self.wiring.encode_deferred(wiring_statement)?;
        let mut link_evaluations =
            Vec::with_capacity(self.link_evaluations.len() * BlsDoryFr::zero().compressed_size());
        for evaluation in &self.link_evaluations {
            append_serialized(&mut link_evaluations, evaluation)?;
        }
        let mut final_output_evaluation = Vec::with_capacity(BlsDoryFr::zero().compressed_size());
        append_serialized(&mut final_output_evaluation, &self.final_output_evaluation)?;
        let mut total = SHARED_PROOF_HEADER_BYTES;
        for matrix in &matrices {
            total = framed_size(total, matrix.len())?;
        }
        for (arithmetic, range) in &transitions {
            total = framed_size(total, arithmetic.len())?;
            total = framed_size(total, range.len())?;
        }
        total = framed_size(total, wiring.len())?;
        total = framed_size(total, link_evaluations.len())?;
        total = framed_size(total, final_output_evaluation.len())?;
        total = framed_size(total, self.opening_proof.len())?;
        if total > MAX_BLS_DORY_SHARED_LAYOUT_PROOF_BYTES {
            return Err(BlsDorySharedLayoutError::ProofTooLarge);
        }
        let mut encoded = Vec::with_capacity(total);
        encoded.extend_from_slice(&SHARED_PROOF_MAGIC);
        encoded.extend_from_slice(&self.protocol_version.to_le_bytes());
        encoded.extend_from_slice(&self.padded_variables.to_le_bytes());
        encoded.extend_from_slice(&(matrices.len() as u16).to_le_bytes());
        encoded.extend_from_slice(&(transitions.len() as u16).to_le_bytes());
        for matrix in &matrices {
            append_framed(&mut encoded, matrix)?;
        }
        for (arithmetic, range) in &transitions {
            append_framed(&mut encoded, arithmetic)?;
            append_framed(&mut encoded, range)?;
        }
        append_framed(&mut encoded, &wiring)?;
        append_framed(&mut encoded, &link_evaluations)?;
        append_framed(&mut encoded, &final_output_evaluation)?;
        append_framed(&mut encoded, &self.opening_proof)?;
        if encoded.len() != total {
            return Err(BlsDorySharedLayoutError::ProofTooLarge);
        }
        Ok(encoded)
    }

    /// Decode the exact component shapes implied by the trusted statements and
    /// shared variable count.
    pub fn decode_with_variables(
        encoded: &[u8],
        matrix_statements: &[StructuredMatrixStatement],
        transition_statements: &[StructuredTransitionStatement],
        wiring_statement: StructuredWiringStatement,
        padded_variables: usize,
    ) -> Result<Self, BlsDorySharedLayoutError> {
        if encoded.len() < SHARED_PROOF_HEADER_BYTES
            || encoded.len() > MAX_BLS_DORY_SHARED_LAYOUT_PROOF_BYTES
            || encoded[..8] != SHARED_PROOF_MAGIC
        {
            return Err(BlsDorySharedLayoutError::InvalidEncoding);
        }
        let protocol_version = read_u16(encoded, 8)?;
        let encoded_variables = read_u16(encoded, 10)?;
        let matrix_count = read_u16(encoded, 12)? as usize;
        let transition_count = read_u16(encoded, 14)? as usize;
        if protocol_version != BLS_DORY_SHARED_LAYOUT_VERSION
            || usize::from(encoded_variables) != padded_variables
            || matrix_count != matrix_statements.len()
            || transition_count != transition_statements.len()
            || !(1..=MAX_BLS_DORY_SHARED_MATRIX_PROOFS).contains(&matrix_count)
            || !(1..=MAX_BLS_DORY_SHARED_TRANSITION_PROOFS).contains(&transition_count)
        {
            return Err(BlsDorySharedLayoutError::InvalidProofShape);
        }
        validate_shared_link_topology(matrix_statements, transition_statements, wiring_statement)?;
        let mut offset = SHARED_PROOF_HEADER_BYTES;
        let mut matrices = Vec::with_capacity(matrix_count);
        for statement in matrix_statements {
            matrices.push(BlsDoryMatrixProof::decode_deferred_with_variables(
                take_framed(encoded, &mut offset)?,
                *statement,
                padded_variables,
            )?);
        }
        let mut transitions = Vec::with_capacity(transition_count);
        for statement in transition_statements {
            let arithmetic = BlsDoryTransitionProof::decode_deferred_with_variables(
                take_framed(encoded, &mut offset)?,
                *statement,
                padded_variables,
            )?;
            let range = BlsDoryRangeLogUpProof::decode_deferred_with_variables(
                take_framed(encoded, &mut offset)?,
                *statement,
                padded_variables,
            )?;
            transitions.push(BlsDoryTransitionRangeProof { arithmetic, range });
        }
        let wiring = BlsDoryWiringProof::decode_deferred_with_variables(
            take_framed(encoded, &mut offset)?,
            wiring_statement,
            padded_variables,
        )?;
        let link_bytes = take_framed(encoded, &mut offset)?;
        let link_count = shared_link_count(matrix_count)?;
        if link_bytes.len()
            != link_count
                .checked_mul(BlsDoryFr::zero().compressed_size())
                .ok_or(BlsDorySharedLayoutError::ProofTooLarge)?
        {
            return Err(BlsDorySharedLayoutError::InvalidProofShape);
        }
        let mut link_reader = Cursor::new(link_bytes);
        let link_evaluations = (0..link_count)
            .map(|_| read_serialized(&mut link_reader))
            .collect::<Result<Vec<_>, _>>()?;
        if link_reader.position() as usize != link_bytes.len() {
            return Err(BlsDorySharedLayoutError::InvalidEncoding);
        }
        let final_output_bytes = take_framed(encoded, &mut offset)?;
        if final_output_bytes.len() != BlsDoryFr::zero().compressed_size() {
            return Err(BlsDorySharedLayoutError::InvalidProofShape);
        }
        let mut final_output_reader = Cursor::new(final_output_bytes);
        let final_output_evaluation = read_serialized(&mut final_output_reader)?;
        if final_output_reader.position() as usize != final_output_bytes.len() {
            return Err(BlsDorySharedLayoutError::InvalidEncoding);
        }
        let opening_proof = take_framed(encoded, &mut offset)?.to_vec();
        if opening_proof.is_empty()
            || opening_proof.len() > MAX_BLS_DORY_AGGREGATE_BYTES
            || offset != encoded.len()
        {
            return Err(BlsDorySharedLayoutError::InvalidProofShape);
        }
        let proof = Self {
            protocol_version,
            padded_variables: encoded_variables,
            matrices,
            transitions,
            wiring,
            link_evaluations,
            final_output_evaluation,
            opening_proof,
        };
        validate_shared_component_shape(&proof, padded_variables)?;
        if proof.encode(matrix_statements, transition_statements, wiring_statement)? != encoded {
            return Err(BlsDorySharedLayoutError::InvalidEncoding);
        }
        Ok(proof)
    }
}

impl BlsDorySharedLayoutV5Proof {
    /// Encode the exact production Layout V5 component order canonically.
    pub fn encode(
        &self,
        matrix_statements: &[StructuredMatrixStatement],
        transition_statements: &[StructuredTransitionStatement],
        wiring_statement: StructuredWiringStatement,
    ) -> Result<Vec<u8>, BlsDorySharedLayoutError> {
        let padded_variables = validate_layout_v5_codec_context(&self.context)?;
        validate_layout_v5_production_statements(
            matrix_statements,
            transition_statements,
            wiring_statement,
        )?;
        validate_shared_component_shape_v5(&self.proof, padded_variables)?;
        if matrix_statements.len() != MAX_BLS_DORY_SHARED_MATRIX_PROOFS
            || transition_statements.len() != MAX_BLS_DORY_SHARED_TRANSITION_PROOFS
        {
            return Err(BlsDorySharedLayoutError::InvalidProofShape);
        }
        validate_shared_link_topology(matrix_statements, transition_statements, wiring_statement)?;

        let matrices = self
            .proof
            .matrices
            .iter()
            .zip(matrix_statements)
            .map(|(proof, statement)| proof.encode_deferred(*statement))
            .collect::<Result<Vec<_>, _>>()?;
        let transitions = self
            .proof
            .transitions
            .iter()
            .zip(transition_statements)
            .map(|(proof, statement)| {
                Ok((
                    proof.arithmetic.encode_deferred(*statement)?,
                    proof.range.encode_deferred(*statement)?,
                ))
            })
            .collect::<Result<Vec<_>, BlsDorySharedLayoutError>>()?;
        let wiring = self.proof.wiring.encode_deferred(wiring_statement)?;
        let mut link_evaluations = Vec::with_capacity(
            self.proof.link_evaluations.len() * BlsDoryFr::zero().compressed_size(),
        );
        for evaluation in &self.proof.link_evaluations {
            append_serialized(&mut link_evaluations, evaluation)?;
        }
        let mut final_output_evaluation = Vec::with_capacity(BlsDoryFr::zero().compressed_size());
        append_serialized(
            &mut final_output_evaluation,
            &self.proof.final_output_evaluation,
        )?;

        let mut total = SHARED_PROOF_HEADER_BYTES;
        for matrix in &matrices {
            total = framed_size(total, matrix.len())?;
        }
        for (arithmetic, range) in &transitions {
            total = framed_size(total, arithmetic.len())?;
            total = framed_size(total, range.len())?;
        }
        total = framed_size(total, wiring.len())?;
        total = framed_size(total, link_evaluations.len())?;
        total = framed_size(total, final_output_evaluation.len())?;
        total = framed_size(total, self.proof.opening_proof.len())?;
        if total > MAX_BLS_DORY_SHARED_LAYOUT_PROOF_BYTES {
            return Err(BlsDorySharedLayoutError::ProofTooLarge);
        }

        let mut encoded = Vec::with_capacity(total);
        encoded.extend_from_slice(&SHARED_PROOF_MAGIC);
        encoded.extend_from_slice(&DORY_V3_SHARED_LAYOUT_VERSION.to_le_bytes());
        encoded.extend_from_slice(&self.proof.padded_variables.to_le_bytes());
        encoded.extend_from_slice(&(matrices.len() as u16).to_le_bytes());
        encoded.extend_from_slice(&(transitions.len() as u16).to_le_bytes());
        for matrix in &matrices {
            append_framed(&mut encoded, matrix)?;
        }
        for (arithmetic, range) in &transitions {
            append_framed(&mut encoded, arithmetic)?;
            append_framed(&mut encoded, range)?;
        }
        append_framed(&mut encoded, &wiring)?;
        append_framed(&mut encoded, &link_evaluations)?;
        append_framed(&mut encoded, &final_output_evaluation)?;
        append_framed(&mut encoded, &self.proof.opening_proof)?;
        if encoded.len() != total {
            return Err(BlsDorySharedLayoutError::ProofTooLarge);
        }
        Ok(encoded)
    }

    /// Decode only authenticated Layout V5. Legacy Layout V4 is never retried
    /// or reinterpreted after a V5 header failure.
    pub fn decode_with_context(
        encoded: &[u8],
        context: &BlsDorySharedLayoutV5Context,
        matrix_statements: &[StructuredMatrixStatement],
        transition_statements: &[StructuredTransitionStatement],
        wiring_statement: StructuredWiringStatement,
    ) -> Result<Self, BlsDorySharedLayoutError> {
        let padded_variables = validate_layout_v5_codec_context(context)?;
        validate_layout_v5_production_statements(
            matrix_statements,
            transition_statements,
            wiring_statement,
        )?;
        if encoded.len() < SHARED_PROOF_HEADER_BYTES
            || encoded.len() > MAX_BLS_DORY_SHARED_LAYOUT_PROOF_BYTES
            || encoded[..8] != SHARED_PROOF_MAGIC
        {
            return Err(BlsDorySharedLayoutError::InvalidEncoding);
        }

        let protocol_version = read_u16(encoded, 8)?;
        let encoded_variables = read_u16(encoded, 10)?;
        let matrix_count = read_u16(encoded, 12)? as usize;
        let transition_count = read_u16(encoded, 14)? as usize;
        if protocol_version != DORY_V3_SHARED_LAYOUT_VERSION
            || usize::from(encoded_variables) != padded_variables
            || matrix_count != MAX_BLS_DORY_SHARED_MATRIX_PROOFS
            || transition_count != MAX_BLS_DORY_SHARED_TRANSITION_PROOFS
            || matrix_statements.len() != MAX_BLS_DORY_SHARED_MATRIX_PROOFS
            || transition_statements.len() != MAX_BLS_DORY_SHARED_TRANSITION_PROOFS
        {
            return Err(BlsDorySharedLayoutError::InvalidProofShape);
        }
        validate_shared_link_topology(matrix_statements, transition_statements, wiring_statement)?;

        let mut offset = SHARED_PROOF_HEADER_BYTES;
        let mut matrices = Vec::with_capacity(matrix_count);
        for statement in matrix_statements {
            matrices.push(BlsDoryMatrixProof::decode_deferred_with_variables(
                take_framed(encoded, &mut offset)?,
                *statement,
                padded_variables,
            )?);
        }
        let mut transitions = Vec::with_capacity(transition_count);
        for statement in transition_statements {
            let arithmetic = BlsDoryTransitionProof::decode_deferred_with_variables(
                take_framed(encoded, &mut offset)?,
                *statement,
                padded_variables,
            )?;
            let range = BlsDoryRangeLogUpProof::decode_deferred_with_variables(
                take_framed(encoded, &mut offset)?,
                *statement,
                padded_variables,
            )?;
            transitions.push(BlsDoryTransitionRangeProof { arithmetic, range });
        }
        let wiring = BlsDoryWiringProof::decode_deferred_with_variables(
            take_framed(encoded, &mut offset)?,
            wiring_statement,
            padded_variables,
        )?;

        let link_bytes = take_framed(encoded, &mut offset)?;
        if link_bytes.len()
            != BLS_DORY_SHARED_PRODUCTION_EQUALITY_LINKS
                .checked_mul(BlsDoryFr::zero().compressed_size())
                .ok_or(BlsDorySharedLayoutError::ProofTooLarge)?
        {
            return Err(BlsDorySharedLayoutError::InvalidProofShape);
        }
        let mut link_reader = Cursor::new(link_bytes);
        let link_evaluations = (0..BLS_DORY_SHARED_PRODUCTION_EQUALITY_LINKS)
            .map(|_| read_serialized(&mut link_reader))
            .collect::<Result<Vec<_>, _>>()?;
        if link_reader.position() as usize != link_bytes.len() {
            return Err(BlsDorySharedLayoutError::InvalidEncoding);
        }

        let final_output_bytes = take_framed(encoded, &mut offset)?;
        if final_output_bytes.len() != BlsDoryFr::zero().compressed_size() {
            return Err(BlsDorySharedLayoutError::InvalidProofShape);
        }
        let mut final_output_reader = Cursor::new(final_output_bytes);
        let final_output_evaluation = read_serialized(&mut final_output_reader)?;
        if final_output_reader.position() as usize != final_output_bytes.len() {
            return Err(BlsDorySharedLayoutError::InvalidEncoding);
        }

        let opening_proof = take_framed(encoded, &mut offset)?.to_vec();
        if opening_proof.is_empty()
            || opening_proof.len() > MAX_BLS_DORY_AGGREGATE_BYTES
            || offset != encoded.len()
        {
            return Err(BlsDorySharedLayoutError::InvalidProofShape);
        }
        let decoded = Self {
            context: *context,
            proof: BlsDorySharedLayoutProof {
                protocol_version,
                padded_variables: encoded_variables,
                matrices,
                transitions,
                wiring,
                link_evaluations,
                final_output_evaluation,
                opening_proof,
            },
        };
        validate_shared_component_shape_v5(&decoded.proof, padded_variables)?;
        if decoded.encode(matrix_statements, transition_statements, wiring_statement)? != encoded {
            return Err(BlsDorySharedLayoutError::InvalidEncoding);
        }
        Ok(decoded)
    }
}

fn validate_layout_v5_codec_context(
    context: &BlsDorySharedLayoutV5Context,
) -> Result<usize, BlsDorySharedLayoutError> {
    let padded_variables = usize::try_from(context.padded_variables)
        .map_err(|_| BlsDorySharedLayoutError::V3Context)?;
    if context.suite_digest != *DORY_V3_PRODUCTION_SUITE_DIGEST
        || context.model_identity_digest == Digest32::ZERO
        || context.setup_identity != DORY_V3_SETUP_IDENTITY
        || context.padded_variables != DORY_V3_PADDED_VARIABLES
        || padded_variables != BLS_DORY_SHARED_PRODUCTION_VARIABLES
    {
        return Err(BlsDorySharedLayoutError::V3Context);
    }
    Ok(padded_variables)
}

#[allow(
    dead_code,
    reason = "used by the candidate-owned V3/V5 integration seam"
)]
fn validate_layout_v5_record_context_binding(
    binding: &[u8],
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    context: BlsDorySharedLayoutV5Context,
    component_binding: BlsDoryFixedModelBindingV2,
    setup: &DeterministicBlsDorySetup,
) -> Result<usize, BlsDorySharedLayoutError> {
    let expected_context =
        BlsDorySharedLayoutV5Context::from_bank_authenticated_record(authenticated, setup)?;
    if context != expected_context {
        return Err(BlsDorySharedLayoutError::V3Context);
    }
    validate_layout_v5_record_context_authority(
        binding,
        authenticated,
        context,
        component_binding,
        setup,
    )?;
    validate_layout_v5_codec_context(&context)
}

fn validate_layout_v5_record_context_authority(
    binding: &[u8],
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    context: BlsDorySharedLayoutV5Context,
    component_binding: BlsDoryFixedModelBindingV2,
    setup: &DeterministicBlsDorySetup,
) -> Result<usize, BlsDorySharedLayoutError> {
    let record = authenticated.record();
    let expected_context = BlsDorySharedLayoutV5Context {
        suite_digest: record.suite_digest(),
        model_identity_digest: record.model_identity_digest(),
        setup_identity: record.setup_identity(),
        padded_variables: record.padded_variables(),
    };
    let padded_variables = usize::try_from(context.padded_variables)
        .map_err(|_| BlsDorySharedLayoutError::V3Context)?;
    if context != expected_context
        || component_binding != context.fixed_model_binding(binding)?
        || context.setup_identity != Digest32::new(setup.identity())
        || padded_variables != setup.max_log_n()
    {
        return Err(BlsDorySharedLayoutError::V3Context);
    }
    Ok(padded_variables)
}

#[allow(
    dead_code,
    reason = "used by the candidate-owned V3/V5 integration seam"
)]
fn validate_layout_v5_prepared_model_commitments(
    prepared_model: &BlsDoryPreparedFixedModelV5,
    model_identity: &DoryV3ModelIdentityV1,
    matrix_statements: &[StructuredMatrixStatement],
    transition_statements: &[StructuredTransitionStatement],
    aggregate_layout: BlsDoryAggregateLayout,
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDorySharedLayoutError> {
    let expected_weights = model_identity.weight_bank_commitments();
    if transition_statements.is_empty()
        || prepared_model.weight_banks.len() != matrix_statements.len()
        || expected_weights.len() != matrix_statements.len()
        || !prepared_model
            .base_input
            .matches_layout(aggregate_layout, setup)
        || prepared_model.base_input.commitment() != model_identity.base_input_commitment()
        || prepared_model.base_input.explicit_coefficient_count()
            != transition_statements[0]
                .elements()
                .map_err(BlsDoryTransitionError::from)?
    {
        return Err(BlsDorySharedLayoutError::FixedModelCommitment);
    }
    for ((prepared_weight, statement), expected) in prepared_model
        .weight_banks
        .iter()
        .zip(matrix_statements)
        .zip(&expected_weights)
    {
        let expected_len = statement
            .table_lengths()
            .map_err(BlsDoryMatrixError::from)?[1];
        if !prepared_weight.matches_layout(aggregate_layout, setup)
            || prepared_weight.commitment() != *expected
            || prepared_weight.explicit_coefficient_count() != expected_len
        {
            return Err(BlsDorySharedLayoutError::FixedModelCommitment);
        }
    }
    Ok(())
}

#[cfg(any(test, feature = "whir-prototype"))]
fn validate_layout_v5_composition_claim_counts(
    shared_claims: usize,
    native_claims: usize,
) -> Result<(), BlsDorySharedLayoutError> {
    if shared_claims != BLS_DORY_SHARED_PRODUCTION_CLAIMS
        || native_claims != BLS_DORY_SHARED_NATIVE_COMPOSITION_CLAIMS
        || shared_claims.checked_add(native_claims) != Some(BLS_DORY_BLAKE3_COMPOSED_OPENING_CLAIMS)
    {
        return Err(BlsDorySharedLayoutError::OpeningClaims);
    }
    Ok(())
}

fn validate_layout_v5_production_statements(
    matrix_statements: &[StructuredMatrixStatement],
    transition_statements: &[StructuredTransitionStatement],
    wiring_statement: StructuredWiringStatement,
) -> Result<(), BlsDorySharedLayoutError> {
    let production = StructuredForgeMatrixResearchShape::production_candidate();
    if matrix_statements != production.matrix_statements.as_slice()
        || transition_statements.first() != Some(&production.initialization_statement)
        || transition_statements.get(1..) != Some(production.transition_statements.as_slice())
        || wiring_statement != production.wiring_statement
    {
        return Err(BlsDorySharedLayoutError::InvalidProofShape);
    }
    Ok(())
}

fn validate_shared_component_shape_v5(
    proof: &BlsDorySharedLayoutProof,
    padded_variables: usize,
) -> Result<(), BlsDorySharedLayoutError> {
    if proof.protocol_version != DORY_V3_SHARED_LAYOUT_VERSION
        || usize::from(proof.padded_variables) != padded_variables
        || proof.matrices.len() != MAX_BLS_DORY_SHARED_MATRIX_PROOFS
        || proof.transitions.len() != MAX_BLS_DORY_SHARED_TRANSITION_PROOFS
        || proof.link_evaluations.len() != BLS_DORY_SHARED_PRODUCTION_EQUALITY_LINKS
        || proof.opening_proof.is_empty()
        || proof.opening_proof.len() > MAX_BLS_DORY_AGGREGATE_BYTES
        || proof.matrices.iter().any(|matrix| {
            usize::from(matrix.padded_variables) != padded_variables
                || !matrix.opening_proof.is_empty()
        })
        || proof.transitions.iter().any(|transition| {
            usize::from(transition.arithmetic.packed_variables) != padded_variables
                || usize::from(transition.range.packed_variables) != padded_variables
                || !transition.arithmetic.opening_proof.is_empty()
                || !transition.range.opening_proof.is_empty()
        })
        || usize::from(proof.wiring.packed_variables) != padded_variables
        || !proof.wiring.opening_proof.is_empty()
    {
        return Err(BlsDorySharedLayoutError::InvalidProofShape);
    }
    Ok(())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BlsDorySharedLayoutError {
    #[error("shared Dory layout projection failed: {0}")]
    Aggregate(#[from] BlsDoryAggregateError),
    #[error("transition arithmetic checkpoint failed: {0}")]
    Transition(#[from] BlsDoryTransitionError),
    #[error("transition range checkpoint failed: {0}")]
    Range(#[from] BlsDoryRangeLogUpError),
    #[error("matrix checkpoint failed: {0}")]
    Matrix(#[from] BlsDoryMatrixError),
    #[error("wiring checkpoint failed: {0}")]
    Wiring(#[from] BlsDoryWiringError),
    #[error("transition arithmetic and range proofs do not share one commitment")]
    TransitionRangeCommitment,
    #[error("shared layout proof has the wrong fixed shape")]
    InvalidProofShape,
    #[error("shared layout proof is too large")]
    ProofTooLarge,
    #[error("shared layout proof encoding is non-canonical or malformed")]
    InvalidEncoding,
    #[error("shared aggregate claims do not match the component transcripts")]
    OpeningClaims,
    #[error("matrix, transition, and wiring statements do not form one canonical topology")]
    LinkTopology,
    #[error("cross-component equality opening evaluations do not match")]
    LinkEvaluation,
    #[error("the pinned BLS fixed-model identity is invalid or mismatched")]
    FixedModelIdentity,
    #[error("the authenticated Dory V3 shared-layout context is invalid or mismatched")]
    V3Context,
    #[error("the proof does not use the pinned BLS fixed-model commitments")]
    FixedModelCommitment,
    #[error("authenticated execution-accumulator artifact failed")]
    ExecutionArtifact,
    #[error("the final activation cannot be derived as canonical bytes")]
    FinalActivation,
    #[cfg(feature = "whir-prototype")]
    #[error("the final-output bridge statement is invalid: {0}")]
    OutputBridge(#[from] BlsDoryOutputBridgeError),
    #[error("the shared BLS12-381 layout is not production ready")]
    NotProductionReady,
}

pub struct BlsDoryMatrixProverInput<'a> {
    pub statement: StructuredMatrixStatement,
    pub activations: &'a [i64],
    pub weights: &'a [i64],
    pub accumulators: &'a [i64],
}

/// Matrix witness whose authenticated fixed-weight polynomial has already been
/// prepared from the pinned model bank. The polynomial is reused for the
/// matrix transcript, terminal evaluation, and shared aggregate opening.
pub struct BlsDoryPrecommittedMatrixProverInput<'a> {
    pub statement: StructuredMatrixStatement,
    pub activations: &'a [i64],
    pub weight: &'a BlsDoryCommittedPolynomial,
    pub accumulators: &'a [i64],
}

/// Layout V5 matrix witness. Fixed weights are selected exclusively from the
/// bank-authenticated prepared-model capability passed to the V5 preparation
/// entry point; callers cannot inject a parallel weight polynomial.
#[allow(
    dead_code,
    reason = "used by the candidate-owned V3/V5 integration seam"
)]
pub(crate) struct BlsDorySharedLayoutV5MatrixProverInput<'a> {
    pub(crate) statement: StructuredMatrixStatement,
    pub(crate) activations: &'a [i64],
    pub(crate) accumulators: &'a [i64],
}

#[derive(Clone, Copy)]
enum SharedMatrixWeight<'a> {
    Signed(&'a [i64]),
    Precommitted(&'a BlsDoryCommittedPolynomial),
}

#[derive(Clone, Copy)]
struct SharedMatrixProverInput<'a> {
    statement: StructuredMatrixStatement,
    activations: &'a [i64],
    weight: SharedMatrixWeight<'a>,
    accumulators: &'a [i64],
}

pub struct BlsDoryTransitionProverInput<'a> {
    pub statement: StructuredTransitionStatement,
    pub mask_polynomial: &'a StructuredMaskPolynomial,
    pub witness: &'a StructuredTransitionWitness,
}

/// Prove all scalar checkpoints with a single opening aggregate. The bounded
/// vectors cover both small fixtures and the exact three-matrix/four-transition
/// production topology.
#[allow(clippy::too_many_arguments)]
pub fn prove_bls_dory_shared_layout_at_variables(
    binding: &[u8],
    trusted_model: &ModelPcsIdentity,
    fixed_model: &BlsDoryFixedModelIdentity,
    matrix_inputs: &[BlsDoryMatrixProverInput<'_>],
    transition_inputs: &[BlsDoryTransitionProverInput<'_>],
    wiring_statement: StructuredWiringStatement,
    initial: &[i64],
    inputs: &[i64],
    outputs: &[i64],
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDorySharedLayoutProof, BlsDorySharedLayoutError> {
    let matrix_inputs = matrix_inputs
        .iter()
        .map(|input| SharedMatrixProverInput {
            statement: input.statement,
            activations: input.activations,
            weight: SharedMatrixWeight::Signed(input.weights),
            accumulators: input.accumulators,
        })
        .collect::<Vec<_>>();
    prove_bls_dory_shared_layout_at_variables_with_optional_scratch(
        binding,
        trusted_model,
        fixed_model,
        &matrix_inputs,
        transition_inputs,
        wiring_statement,
        initial,
        inputs,
        outputs,
        padded_variables,
        setup,
        None,
    )
}

/// Prove the shared scalar layout with authenticated source and fold artifacts.
/// Every padded component commitment streams directly into authenticated
/// source artifacts. Transition folds are authenticated on disk, while LogUp
/// recomputes cell-variable folds and retains only its selector boundary.
#[allow(clippy::too_many_arguments)]
pub fn prove_bls_dory_shared_layout_at_variables_with_scratch(
    binding: &[u8],
    trusted_model: &ModelPcsIdentity,
    fixed_model: &BlsDoryFixedModelIdentity,
    matrix_inputs: &[BlsDoryMatrixProverInput<'_>],
    transition_inputs: &[BlsDoryTransitionProverInput<'_>],
    wiring_statement: StructuredWiringStatement,
    initial: &[i64],
    inputs: &[i64],
    outputs: &[i64],
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<BlsDorySharedLayoutProof, BlsDorySharedLayoutError> {
    let matrix_inputs = matrix_inputs
        .iter()
        .map(|input| SharedMatrixProverInput {
            statement: input.statement,
            activations: input.activations,
            weight: SharedMatrixWeight::Signed(input.weights),
            accumulators: input.accumulators,
        })
        .collect::<Vec<_>>();
    prove_bls_dory_shared_layout_at_variables_with_optional_scratch(
        binding,
        trusted_model,
        fixed_model,
        &matrix_inputs,
        transition_inputs,
        wiring_statement,
        initial,
        inputs,
        outputs,
        padded_variables,
        setup,
        Some(scratch_directory),
    )
}

/// Prove the shared layout while reusing weight polynomials prepared by an
/// authenticated fixed-model stream. No materialized weight slice is accepted
/// on this path, and every supplied commitment must match the pinned identity.
#[allow(clippy::too_many_arguments)]
pub fn prove_bls_dory_shared_layout_with_precommitted_weights_at_variables_with_scratch(
    binding: &[u8],
    trusted_model: &ModelPcsIdentity,
    fixed_model: &BlsDoryFixedModelIdentity,
    matrix_inputs: &[BlsDoryPrecommittedMatrixProverInput<'_>],
    transition_inputs: &[BlsDoryTransitionProverInput<'_>],
    wiring_statement: StructuredWiringStatement,
    initial: &[i64],
    inputs: &[i64],
    outputs: &[i64],
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<BlsDorySharedLayoutProof, BlsDorySharedLayoutError> {
    let matrix_inputs = matrix_inputs
        .iter()
        .map(|input| SharedMatrixProverInput {
            statement: input.statement,
            activations: input.activations,
            weight: SharedMatrixWeight::Precommitted(input.weight),
            accumulators: input.accumulators,
        })
        .collect::<Vec<_>>();
    prove_bls_dory_shared_layout_at_variables_with_optional_scratch(
        binding,
        trusted_model,
        fixed_model,
        &matrix_inputs,
        transition_inputs,
        wiring_statement,
        initial,
        inputs,
        outputs,
        padded_variables,
        setup,
        Some(scratch_directory),
    )
}

/// Prepare the authenticated precommitted-weight shared layout without
/// producing its aggregate opening. The returned state is consumed by the
/// exact 128+6 native BLAKE3 composer.
#[cfg(any(test, feature = "whir-prototype"))]
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_bls_dory_shared_layout_with_precommitted_weights_at_variables_with_scratch(
    binding: &[u8],
    trusted_model: &ModelPcsIdentity,
    fixed_model: &BlsDoryFixedModelIdentity,
    matrix_inputs: &[BlsDoryPrecommittedMatrixProverInput<'_>],
    transition_inputs: &[BlsDoryTransitionProverInput<'_>],
    wiring_statement: StructuredWiringStatement,
    initial: &[i64],
    inputs: &[i64],
    outputs: &[i64],
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<PreparedBlsDorySharedLayoutProverState, BlsDorySharedLayoutError> {
    let matrix_inputs = matrix_inputs
        .iter()
        .map(|input| SharedMatrixProverInput {
            statement: input.statement,
            activations: input.activations,
            weight: SharedMatrixWeight::Precommitted(input.weight),
            accumulators: input.accumulators,
        })
        .collect::<Vec<_>>();
    prepare_bls_dory_shared_layout_at_variables_with_optional_scratch(
        binding,
        trusted_model,
        fixed_model,
        &matrix_inputs,
        transition_inputs,
        wiring_statement,
        initial,
        inputs,
        outputs,
        padded_variables,
        setup,
        Some(scratch_directory),
    )
}

/// Closed authority for preparing one exact Layout V5 from a verified V3
/// execution. Fixed polynomials, statements, and the typed component binding
/// cannot be replaced after this preflight succeeds.
#[cfg(feature = "whir-prototype")]
pub(crate) struct ValidatedBlsDorySharedLayoutV5ExecutionPreparation<'a> {
    context: BlsDorySharedLayoutV5Context,
    component_binding: BlsDoryFixedModelBindingV2,
    prepared_model: &'a BlsDoryPreparedFixedModelV5,
    matrix_statements: [StructuredMatrixStatement; MAX_BLS_DORY_SHARED_MATRIX_PROOFS],
    transition_statements: [StructuredTransitionStatement; MAX_BLS_DORY_SHARED_TRANSITION_PROOFS],
    wiring_statement: StructuredWiringStatement,
    padded_variables: usize,
    #[cfg(test)]
    production: bool,
}

#[cfg(feature = "whir-prototype")]
impl<'a> ValidatedBlsDorySharedLayoutV5ExecutionPreparation<'a> {
    #[allow(clippy::too_many_arguments)]
    fn new_production(
        binding: &[u8],
        authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
        prepared_model: &'a BlsDoryPreparedFixedModelV5,
        context: BlsDorySharedLayoutV5Context,
        component_binding: BlsDoryFixedModelBindingV2,
        matrix_statements: [StructuredMatrixStatement; MAX_BLS_DORY_SHARED_MATRIX_PROOFS],
        transition_statements: [StructuredTransitionStatement;
            MAX_BLS_DORY_SHARED_TRANSITION_PROOFS],
        wiring_statement: StructuredWiringStatement,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<Self, BlsDorySharedLayoutError> {
        let padded_variables = validate_layout_v5_record_context_authority(
            binding,
            authenticated,
            context,
            component_binding,
            setup,
        )?;
        if !prepared_model.is_bound_to_bank_authenticated_record(authenticated) {
            return Err(BlsDorySharedLayoutError::V3Context);
        }
        authenticated
            .record()
            .validate_production(setup)
            .map_err(|_| BlsDorySharedLayoutError::V3Context)?;
        if validate_layout_v5_codec_context(&context)? != padded_variables {
            return Err(BlsDorySharedLayoutError::V3Context);
        }
        validate_layout_v5_production_statements(
            &matrix_statements,
            &transition_statements,
            wiring_statement,
        )?;
        let aggregate_layout = BlsDoryAggregateLayout::new(
            padded_variables / 2,
            padded_variables - padded_variables / 2,
        )?;
        validate_layout_v5_prepared_model_commitments(
            prepared_model,
            authenticated.record().model_identity(),
            &matrix_statements,
            &transition_statements,
            aggregate_layout,
            setup,
        )?;
        Ok(Self {
            context,
            component_binding,
            prepared_model,
            matrix_statements,
            transition_statements,
            wiring_statement,
            padded_variables,
            #[cfg(test)]
            production: true,
        })
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn new_for_test(
        binding: &[u8],
        authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
        prepared_model: &'a BlsDoryPreparedFixedModelV5,
        context: BlsDorySharedLayoutV5Context,
        component_binding: BlsDoryFixedModelBindingV2,
        matrix_statements: [StructuredMatrixStatement; MAX_BLS_DORY_SHARED_MATRIX_PROOFS],
        transition_statements: [StructuredTransitionStatement;
            MAX_BLS_DORY_SHARED_TRANSITION_PROOFS],
        wiring_statement: StructuredWiringStatement,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<Self, BlsDorySharedLayoutError> {
        let padded_variables = validate_layout_v5_record_context_authority(
            binding,
            authenticated,
            context,
            component_binding,
            setup,
        )?;
        if !prepared_model.is_bound_to_bank_authenticated_record(authenticated) {
            return Err(BlsDorySharedLayoutError::V3Context);
        }
        validate_shared_link_topology(
            &matrix_statements,
            &transition_statements,
            wiring_statement,
        )?;
        let aggregate_layout = BlsDoryAggregateLayout::new(
            padded_variables / 2,
            padded_variables - padded_variables / 2,
        )?;
        validate_layout_v5_prepared_model_commitments(
            prepared_model,
            authenticated.record().model_identity(),
            &matrix_statements,
            &transition_statements,
            aggregate_layout,
            setup,
        )?;
        Ok(Self {
            context,
            component_binding,
            prepared_model,
            matrix_statements,
            transition_statements,
            wiring_statement,
            padded_variables,
            production: false,
        })
    }

    pub(crate) const fn component_binding(&self) -> BlsDoryFixedModelBindingV2 {
        self.component_binding
    }

    pub(crate) const fn padded_variables(&self) -> usize {
        self.padded_variables
    }

    pub(crate) const fn matrix_count(&self) -> usize {
        self.matrix_statements.len()
    }

    pub(crate) const fn transition_count(&self) -> usize {
        self.transition_statements.len()
    }

    pub(crate) const fn execution_geometry(&self) -> (usize, usize, usize, usize) {
        (
            self.wiring_statement.rows,
            self.wiring_statement.cols,
            self.wiring_statement.banks,
            self.wiring_statement.layers_per_bank,
        )
    }

    pub(crate) fn matrix_weight(
        &self,
        bank: usize,
    ) -> Result<&BlsDoryCommittedPolynomial, BlsDorySharedLayoutError> {
        self.prepared_model
            .weight_banks
            .get(bank)
            .ok_or(BlsDorySharedLayoutError::InvalidProofShape)
    }

    pub(crate) fn transition_statement(
        &self,
        index: usize,
    ) -> Result<StructuredTransitionStatement, BlsDorySharedLayoutError> {
        self.transition_statements
            .get(index)
            .copied()
            .ok_or(BlsDorySharedLayoutError::InvalidProofShape)
    }

    pub(crate) fn into_prepared(
        self,
        matrices: Vec<PreparedBlsDoryMatrixProof>,
        transitions: Vec<(
            PreparedBlsDoryTransitionProof,
            PreparedBlsDoryRangeLogUpProof,
        )>,
        wiring: PreparedBlsDoryWiringProof,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<PreparedBlsDorySharedLayoutV5ProverState, BlsDorySharedLayoutError> {
        let fixed_base = self.prepared_model.base_input.clone();
        #[cfg(test)]
        if !self.production {
            return prepare_prepared_shared_layout_v5_validated(
                self.context,
                self.component_binding,
                matrices,
                transitions,
                wiring,
                fixed_base,
                &self.matrix_statements,
                &self.transition_statements,
                self.wiring_statement,
                self.padded_variables,
            );
        }
        prepare_prepared_shared_layout_v5(
            self.context,
            self.component_binding,
            matrices,
            transitions,
            wiring,
            fixed_base,
            &self.matrix_statements,
            &self.transition_statements,
            self.wiring_statement,
            self.padded_variables,
            setup,
        )
    }
}

/// Authenticate every fixed Layout V5 authority before a verified execution
/// artifact or proof scratch is touched.
#[cfg(feature = "whir-prototype")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn preflight_bls_dory_shared_layout_v5_execution_preparation<'a>(
    binding: &[u8],
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    prepared_model: &'a BlsDoryPreparedFixedModelV5,
    context: BlsDorySharedLayoutV5Context,
    component_binding: BlsDoryFixedModelBindingV2,
    setup: &DeterministicBlsDorySetup,
) -> Result<ValidatedBlsDorySharedLayoutV5ExecutionPreparation<'a>, BlsDorySharedLayoutError> {
    let production = StructuredForgeMatrixResearchShape::production_candidate();
    let transition_statements = [
        production.initialization_statement,
        production.transition_statements[0],
        production.transition_statements[1],
        production.transition_statements[2],
    ];
    ValidatedBlsDorySharedLayoutV5ExecutionPreparation::new_production(
        binding,
        authenticated,
        prepared_model,
        context,
        component_binding,
        production.matrix_statements,
        transition_statements,
        production.wiring_statement,
        setup,
    )
}

#[cfg(all(test, feature = "whir-prototype"))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn preflight_bls_dory_shared_layout_v5_execution_preparation_for_test<'a>(
    binding: &[u8],
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    prepared_model: &'a BlsDoryPreparedFixedModelV5,
    context: BlsDorySharedLayoutV5Context,
    component_binding: BlsDoryFixedModelBindingV2,
    setup: &DeterministicBlsDorySetup,
) -> Result<ValidatedBlsDorySharedLayoutV5ExecutionPreparation<'a>, BlsDorySharedLayoutError> {
    let identity = authenticated.record().model_identity();
    let banks = usize::try_from(
        identity
            .weight_bank_count()
            .map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)?,
    )
    .map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)?;
    let layers = usize::try_from(identity.layers_per_bank())
        .map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)?;
    let rows = usize::try_from(identity.batch())
        .map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)?;
    let columns = usize::try_from(identity.dimension())
        .map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)?;
    if banks != MAX_BLS_DORY_SHARED_MATRIX_PROOFS {
        return Err(BlsDorySharedLayoutError::InvalidProofShape);
    }
    let matrix = StructuredMatrixStatement {
        layers,
        rows,
        inner: columns,
        cols: columns,
        max_abs_activation: 125,
        max_abs_weight: 125,
        max_abs_accumulator: 64_000_000,
    };
    let transition = StructuredTransitionStatement {
        layers,
        rows,
        cols: columns,
        max_abs_accumulator: 64_000_000,
        max_mask: 5_000,
    };
    let transition_statements = [
        StructuredTransitionStatement {
            layers: 1,
            rows,
            cols: columns,
            max_abs_accumulator: 125,
            max_mask: 5_000,
        },
        transition,
        transition,
        transition,
    ];
    ValidatedBlsDorySharedLayoutV5ExecutionPreparation::new_for_test(
        binding,
        authenticated,
        prepared_model,
        context,
        component_binding,
        [matrix; MAX_BLS_DORY_SHARED_MATRIX_PROOFS],
        transition_statements,
        StructuredWiringStatement {
            banks,
            layers_per_bank: layers,
            rows,
            cols: columns,
            max_abs_activation: 125,
        },
        setup,
    )
}

/// Prepare the exact production Layout V5 from fixed polynomials that were
/// published only after the same Record V2 model bank authenticated.
#[allow(clippy::too_many_arguments)]
#[allow(
    dead_code,
    reason = "used by the candidate-owned V3/V5 integration seam"
)]
pub(crate) fn prepare_bls_dory_shared_layout_v5_with_precommitted_weights_with_scratch(
    binding: &[u8],
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    prepared_model: &BlsDoryPreparedFixedModelV5,
    context: BlsDorySharedLayoutV5Context,
    component_binding: BlsDoryFixedModelBindingV2,
    matrix_inputs: &[BlsDorySharedLayoutV5MatrixProverInput<'_>],
    transition_inputs: &[BlsDoryTransitionProverInput<'_>],
    wiring_statement: StructuredWiringStatement,
    initial: &[i64],
    inputs: &[i64],
    outputs: &[i64],
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<PreparedBlsDorySharedLayoutV5ProverState, BlsDorySharedLayoutError> {
    let padded_variables = validate_layout_v5_record_context_binding(
        binding,
        authenticated,
        context,
        component_binding,
        setup,
    )?;
    if !prepared_model.is_bound_to_bank_authenticated_record(authenticated) {
        return Err(BlsDorySharedLayoutError::V3Context);
    }
    if matrix_inputs.len() != MAX_BLS_DORY_SHARED_MATRIX_PROOFS
        || transition_inputs.len() != MAX_BLS_DORY_SHARED_TRANSITION_PROOFS
    {
        return Err(BlsDorySharedLayoutError::InvalidProofShape);
    }
    let matrix_statements = matrix_inputs
        .iter()
        .map(|input| input.statement)
        .collect::<Vec<_>>();
    let transition_statements = transition_inputs
        .iter()
        .map(|input| input.statement)
        .collect::<Vec<_>>();
    validate_layout_v5_production_statements(
        &matrix_statements,
        &transition_statements,
        wiring_statement,
    )?;
    for input in transition_inputs {
        input
            .mask_polynomial
            .validate(input.statement)
            .map_err(BlsDoryTransitionError::from)?;
    }

    let aggregate_layout = BlsDoryAggregateLayout::new(
        padded_variables / 2,
        padded_variables - padded_variables / 2,
    )?;
    let model_identity = authenticated.record().model_identity();
    validate_layout_v5_prepared_model_commitments(
        prepared_model,
        model_identity,
        &matrix_statements,
        &transition_statements,
        aggregate_layout,
        setup,
    )?;
    // Reject malformed successor tables before any matrix or transition proof
    // work. The wiring prover repeats these checks at its own trust boundary.
    validate_streaming_tables(wiring_statement, initial, inputs, outputs)
        .map_err(BlsDoryWiringError::from)?;
    validate_successors(wiring_statement, initial, inputs, outputs)
        .map_err(BlsDoryWiringError::from)?;
    let expected_weights = model_identity.weight_bank_commitments();

    let mut matrices = Vec::with_capacity(matrix_inputs.len());
    for ((input, weight), expected) in matrix_inputs
        .iter()
        .zip(&prepared_model.weight_banks)
        .zip(&expected_weights)
    {
        let matrix = prove_bls_dory_matrix_deferred_with_precommitted_weight_and_scratch(
            component_binding.as_bytes(),
            input.statement,
            input.activations,
            weight,
            input.accumulators,
            padded_variables,
            setup,
            scratch_directory,
        )?;
        if matrix.proof.weight_commitment != *expected {
            return Err(BlsDorySharedLayoutError::FixedModelCommitment);
        }
        matrices.push(matrix);
    }

    let mut transitions = Vec::with_capacity(transition_inputs.len());
    let mut released_transition_sources = Vec::with_capacity(transition_inputs.len());
    for input in transition_inputs {
        let mut arithmetic = prove_bls_dory_transition_deferred_at_variables_with_scratch(
            component_binding.as_bytes(),
            input.statement,
            input.mask_polynomial,
            input.witness,
            padded_variables,
            setup,
            scratch_directory,
        )?;
        let transition = arithmetic
            .openings
            .polynomial(0)
            .ok_or(BlsDorySharedLayoutError::OpeningClaims)?;
        let mut range = if input
            .statement
            .elements()
            .map_err(BlsDoryTransitionError::Structured)?
            >= BLS_DORY_RANGE_LOGUP_TABLE_VALUES
        {
            prove_bls_dory_range_logup_deferred_with_precommitted_compact_transition_and_scratch(
                component_binding.as_bytes(),
                input.statement,
                transition,
                padded_variables,
                setup,
                scratch_directory,
            )?
        } else {
            prove_bls_dory_range_logup_deferred_with_precommitted_transition_and_scratch(
                component_binding.as_bytes(),
                input.statement,
                input.witness,
                transition,
                padded_variables,
                setup,
                scratch_directory,
            )?
        };
        if arithmetic.proof.oracle_commitment != range.proof.transition_commitment {
            return Err(BlsDorySharedLayoutError::TransitionRangeCommitment);
        }
        let arithmetic_source = arithmetic
            .openings
            .release_compact_source()?
            .ok_or(BlsDorySharedLayoutError::OpeningClaims)?;
        let range_source = range
            .openings
            .release_compact_source()?
            .ok_or(BlsDorySharedLayoutError::OpeningClaims)?;
        if arithmetic_source != range_source {
            return Err(BlsDorySharedLayoutError::OpeningClaims);
        }
        transitions.push((arithmetic, range));
        released_transition_sources.push(arithmetic_source);
    }
    let wiring = prove_bls_dory_wiring_deferred_at_variables_with_scratch(
        component_binding.as_bytes(),
        wiring_statement,
        initial,
        inputs,
        outputs,
        padded_variables,
        setup,
        scratch_directory,
    )?;

    let rows = 1usize
        .checked_shl(
            u32::try_from(aggregate_layout.nu())
                .map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)?,
        )
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let columns = 1usize
        .checked_shl(
            u32::try_from(aggregate_layout.sigma())
                .map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)?,
        )
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    for (((arithmetic, range), input), expected_source) in transitions
        .iter_mut()
        .zip(transition_inputs)
        .zip(&released_transition_sources)
    {
        let mut source =
            BlsDoryTransitionWitnessRowSource::new(input.statement, input.witness, rows, columns)?;
        let restored = regenerate_bls_dory_compact_row_source_with_scratch(
            &mut source,
            expected_source,
            aggregate_layout.nu(),
            aggregate_layout.sigma(),
            setup,
            scratch_directory,
        )?;
        arithmetic.openings.restore_compact_source(&restored)?;
        range.openings.restore_compact_source(&restored)?;
    }

    prepare_prepared_shared_layout_v5(
        context,
        component_binding,
        matrices,
        transitions,
        wiring,
        prepared_model.base_input.clone(),
        &matrix_statements,
        &transition_statements,
        wiring_statement,
        padded_variables,
        setup,
    )
}

/// Read the final bank's final activation directly from the authenticated
/// execution trace. Only one authentication chunk is buffered in addition to
/// the returned canonical byte string.
#[cfg(any(test, feature = "whir-prototype"))]
pub(crate) fn extract_bls_dory_final_activation_from_execution_artifact(
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    artifact: &mut BlsDoryExecutionAccumulatorArtifact,
    expected_context: BlsDoryExecutionAccumulatorArtifactContext,
) -> Result<Vec<u8>, BlsDorySharedLayoutError> {
    statement
        .validate_verifier_shape()
        .map_err(BlsDoryTransitionError::from)?;
    mask_polynomial
        .validate(statement)
        .map_err(BlsDoryTransitionError::from)?;
    let final_bank = expected_context
        .banks()
        .checked_sub(1)
        .ok_or(BlsDorySharedLayoutError::FinalActivation)?;
    let final_layer = expected_context
        .layers_per_bank()
        .checked_sub(1)
        .ok_or(BlsDorySharedLayoutError::FinalActivation)?;
    let cells = expected_context.cells_per_column();
    if artifact.context() != expected_context
        || statement.layers != expected_context.layers_per_bank()
        || statement.rows != expected_context.canonical_rows()
        || statement.cols != expected_context.canonical_columns()
        || statement.elements().map_err(BlsDoryTransitionError::from)?
            != cells
                .checked_mul(expected_context.layers_per_bank())
                .ok_or(BlsDorySharedLayoutError::FinalActivation)?
    {
        return Err(BlsDorySharedLayoutError::ExecutionArtifact);
    }
    let first_layer = final_bank
        .checked_mul(expected_context.layers_per_bank())
        .and_then(|layer| u32::try_from(layer).ok())
        .ok_or(BlsDorySharedLayoutError::FinalActivation)?;
    let expected_mask = StructuredMaskPolynomial::from_challenge_at_layer_offset(
        &expected_context.challenge_identity(),
        first_layer,
        expected_context.layers_per_bank(),
        expected_context.canonical_rows(),
        expected_context.canonical_columns(),
    )
    .map_err(|_| BlsDorySharedLayoutError::ExecutionArtifact)?;
    if mask_polynomial != &expected_mask {
        return Err(BlsDorySharedLayoutError::ExecutionArtifact);
    }

    let chunk_cells = expected_context.authentication_chunk_cells();
    let mut accumulators = Vec::new();
    accumulators
        .try_reserve_exact(chunk_cells)
        .map_err(|_| BlsDorySharedLayoutError::FinalActivation)?;
    accumulators.resize(chunk_cells, 0_i32);
    let mut activation = Vec::new();
    activation
        .try_reserve_exact(cells)
        .map_err(|_| BlsDorySharedLayoutError::FinalActivation)?;
    let layer_offset = final_layer
        .checked_mul(cells)
        .ok_or(BlsDorySharedLayoutError::FinalActivation)?;
    let column = BlsDoryExecutionAccumulatorColumn::BankLayer {
        bank: final_bank,
        layer: final_layer,
    };
    let mut start = 0usize;
    while start < cells {
        let take = (cells - start).min(chunk_cells);
        artifact
            .read_column_segment(column, start, &mut accumulators[..take])
            .map_err(|_| BlsDorySharedLayoutError::ExecutionArtifact)?;
        for (offset, accumulator) in accumulators[..take].iter().copied().enumerate() {
            let index = layer_offset
                .checked_add(start)
                .and_then(|index| index.checked_add(offset))
                .ok_or(BlsDorySharedLayoutError::FinalActivation)?;
            let mask = mask_polynomial
                .value_at_boolean_index_prevalidated(statement, index)
                .map_err(|_| BlsDorySharedLayoutError::FinalActivation)?;
            let signed = derive_transition_regular_row_from_mask(
                statement,
                index,
                i64::from(accumulator),
                mask,
            )?
            .activation;
            let byte = signed
                .checked_add(125)
                .filter(|value| *value <= 250)
                .and_then(|value| u8::try_from(value).ok())
                .ok_or(BlsDorySharedLayoutError::FinalActivation)?;
            activation.push(byte);
        }
        start += take;
    }
    if activation.len() != cells {
        return Err(BlsDorySharedLayoutError::FinalActivation);
    }
    Ok(activation)
}

/// Prepare the complete shared layout directly from one authenticated
/// execution trace. The returned state owns every coefficient capability it
/// needs for aggregation and therefore does not retain a borrow of `artifact`.
#[cfg(any(test, feature = "whir-prototype"))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_bls_dory_shared_layout_from_execution_artifact_with_scratch(
    binding: &[u8],
    trusted_model: &ModelPcsIdentity,
    prepared_model: &BlsDoryPreparedFixedModel,
    matrix_statements: &[StructuredMatrixStatement],
    transition_statements: &[StructuredTransitionStatement],
    mask_polynomials: &[&StructuredMaskPolynomial],
    wiring_statement: StructuredWiringStatement,
    artifact: &mut BlsDoryExecutionAccumulatorArtifact,
    expected_context: BlsDoryExecutionAccumulatorArtifactContext,
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<PreparedBlsDorySharedLayoutProverState, BlsDorySharedLayoutError> {
    validate_execution_artifact_shared_layout(
        binding,
        trusted_model,
        prepared_model,
        matrix_statements,
        transition_statements,
        mask_polynomials,
        wiring_statement,
        artifact,
        expected_context,
        padded_variables,
        setup,
    )?;
    let fixed_model = prepared_model.identity();
    let component_binding = fixed_model_binding(binding, trusted_model, fixed_model, setup)?;
    let fixed_base = prepared_model.base_input().clone();

    let mut matrices = Vec::with_capacity(matrix_statements.len());
    for (bank, (statement, weight)) in matrix_statements
        .iter()
        .zip(prepared_model.weight_banks())
        .enumerate()
    {
        let prior_index = if bank == 0 { 0 } else { bank };
        let matrix = prove_bls_dory_matrix_deferred_with_precommitted_weight_from_execution_artifact_and_scratch(
            &component_binding,
            *statement,
            weight,
            artifact,
            expected_context,
            BlsDoryExecutionArtifactMatrixInput {
                bank,
                prior_statement: transition_statements[prior_index],
                prior_mask: mask_polynomials[prior_index],
                current_statement: transition_statements[bank + 1],
                current_mask: mask_polynomials[bank + 1],
            },
            padded_variables,
            setup,
            scratch_directory,
        )?;
        if matrix.proof.weight_commitment != fixed_model.weight_bank_commitments[bank] {
            return Err(BlsDorySharedLayoutError::FixedModelCommitment);
        }
        matrices.push(matrix);
    }

    let mut transitions = Vec::with_capacity(transition_statements.len());
    let mut released_transition_sources = Vec::with_capacity(transition_statements.len());
    for (index, (statement, mask_polynomial)) in transition_statements
        .iter()
        .zip(mask_polynomials)
        .enumerate()
    {
        let transition = execution_artifact_transition(index);
        let mut arithmetic =
            prove_bls_dory_transition_deferred_from_execution_artifact_with_scratch(
                &component_binding,
                *statement,
                mask_polynomial,
                artifact,
                expected_context,
                transition,
                padded_variables,
                setup,
                scratch_directory,
            )?;
        let committed_transition = arithmetic
            .openings
            .polynomial(0)
            .ok_or(BlsDorySharedLayoutError::OpeningClaims)?;
        let mut range = if statement
            .elements()
            .map_err(BlsDoryTransitionError::Structured)?
            >= BLS_DORY_RANGE_LOGUP_TABLE_VALUES
        {
            prove_bls_dory_range_logup_deferred_with_precommitted_compact_transition_and_scratch(
                &component_binding,
                *statement,
                committed_transition,
                padded_variables,
                setup,
                scratch_directory,
            )?
        } else {
            let nu = padded_variables / 2;
            let sigma = padded_variables - nu;
            let rows = 1usize
                .checked_shl(
                    u32::try_from(nu).map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)?,
                )
                .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
            let columns = 1usize
                .checked_shl(
                    u32::try_from(sigma)
                        .map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)?,
                )
                .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
            let source = BlsDoryTransitionWitnessRowSource::new_from_execution_artifact(
                *statement,
                mask_polynomial,
                artifact,
                expected_context,
                transition,
                rows,
                columns,
            )?;
            prove_bls_dory_range_logup_deferred_with_precommitted_row_source_and_scratch(
                &component_binding,
                *statement,
                &source,
                committed_transition,
                padded_variables,
                setup,
                scratch_directory,
            )?
        };
        if arithmetic.proof.oracle_commitment != range.proof.transition_commitment {
            return Err(BlsDorySharedLayoutError::TransitionRangeCommitment);
        }
        let arithmetic_source = arithmetic
            .openings
            .release_compact_source()?
            .ok_or(BlsDorySharedLayoutError::OpeningClaims)?;
        let range_source = range
            .openings
            .release_compact_source()?
            .ok_or(BlsDorySharedLayoutError::OpeningClaims)?;
        if arithmetic_source != range_source {
            return Err(BlsDorySharedLayoutError::OpeningClaims);
        }
        transitions.push((arithmetic, range));
        released_transition_sources.push(arithmetic_source);
    }

    let wiring = prove_bls_dory_wiring_deferred_from_execution_artifact_with_scratch(
        &component_binding,
        wiring_statement,
        transition_statements,
        mask_polynomials,
        artifact,
        expected_context,
        padded_variables,
        setup,
        scratch_directory,
    )?;

    for (index, ((((arithmetic, range), statement), mask_polynomial), expected)) in transitions
        .iter_mut()
        .zip(transition_statements)
        .zip(mask_polynomials)
        .zip(&released_transition_sources)
        .enumerate()
    {
        let restored =
            regenerate_bls_dory_transition_compact_source_from_execution_artifact_with_scratch(
                *statement,
                mask_polynomial,
                artifact,
                expected_context,
                execution_artifact_transition(index),
                padded_variables,
                expected,
                setup,
                scratch_directory,
            )?;
        arithmetic.openings.restore_compact_source(&restored)?;
        range.openings.restore_compact_source(&restored)?;
    }

    prepare_prepared_shared_layout(
        &component_binding,
        matrices,
        transitions,
        wiring,
        fixed_base,
        fixed_model,
        matrix_statements,
        transition_statements,
        wiring_statement,
        padded_variables,
        setup,
    )
}

#[cfg(any(test, feature = "whir-prototype"))]
#[allow(clippy::too_many_arguments)]
fn validate_execution_artifact_shared_layout(
    binding: &[u8],
    trusted_model: &ModelPcsIdentity,
    prepared_model: &BlsDoryPreparedFixedModel,
    matrix_statements: &[StructuredMatrixStatement],
    transition_statements: &[StructuredTransitionStatement],
    mask_polynomials: &[&StructuredMaskPolynomial],
    wiring_statement: StructuredWiringStatement,
    artifact: &mut BlsDoryExecutionAccumulatorArtifact,
    expected_context: BlsDoryExecutionAccumulatorArtifactContext,
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDorySharedLayoutError> {
    if binding.len() > MAX_SHARED_LAYOUT_BINDING_BYTES
        || !(1..=MAX_BLS_DORY_SHARED_MATRIX_PROOFS).contains(&matrix_statements.len())
        || !(1..=MAX_BLS_DORY_SHARED_TRANSITION_PROOFS).contains(&transition_statements.len())
        || transition_statements.len() != matrix_statements.len() + 1
        || mask_polynomials.len() != transition_statements.len()
        || prepared_model.weight_banks().len() != matrix_statements.len()
        || padded_variables == 0
        || padded_variables > setup.max_log_n()
    {
        return Err(BlsDorySharedLayoutError::InvalidProofShape);
    }
    validate_shared_link_topology(matrix_statements, transition_statements, wiring_statement)?;
    validate_fixed_model_topology(
        trusted_model,
        prepared_model.identity(),
        matrix_statements,
        transition_statements,
        wiring_statement,
        setup,
    )?;
    if artifact.context() != expected_context
        || expected_context.setup_identity() != setup.identity()
        || expected_context.banks() != matrix_statements.len()
        || expected_context.layers_per_bank() != wiring_statement.layers_per_bank
        || expected_context.canonical_rows() != wiring_statement.rows
        || expected_context.canonical_columns() != wiring_statement.cols
    {
        return Err(BlsDorySharedLayoutError::ExecutionArtifact);
    }
    wiring_statement
        .validate_verifier_shape()
        .map_err(BlsDoryWiringError::from)?;
    for statement in matrix_statements {
        statement
            .validate_verifier_shape()
            .map_err(BlsDoryMatrixError::from)?;
    }
    for statement in transition_statements {
        statement
            .validate_verifier_shape()
            .map_err(BlsDoryTransitionError::from)?;
    }
    for (index, (statement, mask_polynomial)) in transition_statements
        .iter()
        .zip(mask_polynomials)
        .enumerate()
    {
        mask_polynomial
            .validate(*statement)
            .map_err(BlsDoryTransitionError::from)?;
        let expected_mask = if index == 0 {
            StructuredMaskPolynomial::from_virtual_challenge(
                &expected_context.challenge_identity(),
                expected_context.canonical_rows(),
                expected_context.canonical_columns(),
            )
        } else {
            let first_layer = (index - 1)
                .checked_mul(expected_context.layers_per_bank())
                .and_then(|layer| u32::try_from(layer).ok())
                .ok_or(BlsDorySharedLayoutError::ExecutionArtifact)?;
            StructuredMaskPolynomial::from_challenge_at_layer_offset(
                &expected_context.challenge_identity(),
                first_layer,
                expected_context.layers_per_bank(),
                expected_context.canonical_rows(),
                expected_context.canonical_columns(),
            )
        }
        .map_err(|_| BlsDorySharedLayoutError::ExecutionArtifact)?;
        if *mask_polynomial != &expected_mask {
            return Err(BlsDorySharedLayoutError::ExecutionArtifact);
        }
    }
    let aggregate_layout = BlsDoryAggregateLayout::new(
        padded_variables / 2,
        padded_variables - padded_variables / 2,
    )?;
    let fixed_model = prepared_model.identity();
    if !prepared_model
        .base_input()
        .matches_layout(aggregate_layout, setup)
        || prepared_model.base_input().commitment() != fixed_model.base_input_commitment
        || prepared_model.base_input().explicit_coefficient_count()
            != transition_statements[0]
                .elements()
                .map_err(BlsDoryTransitionError::from)?
        || prepared_model
            .weight_banks()
            .iter()
            .zip(matrix_statements)
            .zip(&fixed_model.weight_bank_commitments)
            .any(|((weight, statement), expected)| {
                let expected_len = statement.table_lengths().ok().map(|lengths| lengths[1]);
                !weight.matches_layout(aggregate_layout, setup)
                    || weight.commitment() != *expected
                    || Some(weight.explicit_coefficient_count()) != expected_len
            })
    {
        return Err(BlsDorySharedLayoutError::FixedModelCommitment);
    }
    artifact
        .authenticate(&expected_context)
        .map_err(|_| BlsDorySharedLayoutError::ExecutionArtifact)
}

#[cfg(any(test, feature = "whir-prototype"))]
const fn execution_artifact_transition(index: usize) -> BlsDoryExecutionAccumulatorTransition {
    if index == 0 {
        BlsDoryExecutionAccumulatorTransition::Initialization
    } else {
        BlsDoryExecutionAccumulatorTransition::Bank(index - 1)
    }
}

#[allow(clippy::too_many_arguments)]
fn prove_bls_dory_shared_layout_at_variables_with_optional_scratch(
    binding: &[u8],
    trusted_model: &ModelPcsIdentity,
    fixed_model: &BlsDoryFixedModelIdentity,
    matrix_inputs: &[SharedMatrixProverInput<'_>],
    transition_inputs: &[BlsDoryTransitionProverInput<'_>],
    wiring_statement: StructuredWiringStatement,
    initial: &[i64],
    inputs: &[i64],
    outputs: &[i64],
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: Option<&Path>,
) -> Result<BlsDorySharedLayoutProof, BlsDorySharedLayoutError> {
    let prepared = prepare_bls_dory_shared_layout_at_variables_with_optional_scratch(
        binding,
        trusted_model,
        fixed_model,
        matrix_inputs,
        transition_inputs,
        wiring_statement,
        initial,
        inputs,
        outputs,
        padded_variables,
        setup,
        scratch_directory,
    )?;
    finish_prepared_shared_layout(prepared, setup, scratch_directory)
}

#[allow(clippy::too_many_arguments)]
fn prepare_bls_dory_shared_layout_at_variables_with_optional_scratch(
    binding: &[u8],
    trusted_model: &ModelPcsIdentity,
    fixed_model: &BlsDoryFixedModelIdentity,
    matrix_inputs: &[SharedMatrixProverInput<'_>],
    transition_inputs: &[BlsDoryTransitionProverInput<'_>],
    wiring_statement: StructuredWiringStatement,
    initial: &[i64],
    inputs: &[i64],
    outputs: &[i64],
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: Option<&Path>,
) -> Result<PreparedBlsDorySharedLayoutProverState, BlsDorySharedLayoutError> {
    if binding.len() > MAX_SHARED_LAYOUT_BINDING_BYTES
        || !(1..=MAX_BLS_DORY_SHARED_MATRIX_PROOFS).contains(&matrix_inputs.len())
        || !(1..=MAX_BLS_DORY_SHARED_TRANSITION_PROOFS).contains(&transition_inputs.len())
        || transition_inputs.len() != matrix_inputs.len() + 1
    {
        return Err(BlsDorySharedLayoutError::InvalidProofShape);
    }
    let matrix_statements = matrix_inputs
        .iter()
        .map(|input| input.statement)
        .collect::<Vec<_>>();
    let transition_statements = transition_inputs
        .iter()
        .map(|input| input.statement)
        .collect::<Vec<_>>();
    validate_shared_link_topology(&matrix_statements, &transition_statements, wiring_statement)?;
    validate_fixed_model_topology(
        trusted_model,
        fixed_model,
        &matrix_statements,
        &transition_statements,
        wiring_statement,
        setup,
    )?;
    let component_binding = fixed_model_binding(binding, trusted_model, fixed_model, setup)?;
    let fixed_base = commit_fixed_table_with_optional_scratch(
        &transition_inputs[0].witness.accumulators,
        padded_variables,
        setup,
        scratch_directory,
    )?;
    if fixed_base.commitment() != fixed_model.base_input_commitment {
        return Err(BlsDorySharedLayoutError::FixedModelCommitment);
    }
    let mut matrices = Vec::with_capacity(matrix_inputs.len());
    for (input, expected_weight) in matrix_inputs
        .iter()
        .zip(&fixed_model.weight_bank_commitments)
    {
        let matrix = match (input.weight, scratch_directory) {
            (SharedMatrixWeight::Signed(weights), Some(scratch_directory)) => {
                prove_bls_dory_matrix_deferred_at_variables_with_scratch(
                    &component_binding,
                    input.statement,
                    input.activations,
                    weights,
                    input.accumulators,
                    padded_variables,
                    setup,
                    scratch_directory,
                )?
            }
            (SharedMatrixWeight::Signed(weights), None) => {
                prove_bls_dory_matrix_deferred_at_variables(
                    &component_binding,
                    input.statement,
                    input.activations,
                    weights,
                    input.accumulators,
                    padded_variables,
                    setup,
                )?
            }
            (SharedMatrixWeight::Precommitted(weight), Some(scratch_directory)) => {
                if weight.commitment() != *expected_weight {
                    return Err(BlsDorySharedLayoutError::FixedModelCommitment);
                }
                prove_bls_dory_matrix_deferred_with_precommitted_weight_and_scratch(
                    &component_binding,
                    input.statement,
                    input.activations,
                    weight,
                    input.accumulators,
                    padded_variables,
                    setup,
                    scratch_directory,
                )?
            }
            (SharedMatrixWeight::Precommitted(_), None) => {
                return Err(BlsDorySharedLayoutError::FixedModelCommitment);
            }
        };
        if matrix.proof.weight_commitment != *expected_weight {
            return Err(BlsDorySharedLayoutError::FixedModelCommitment);
        }
        matrices.push(matrix);
    }
    let mut transitions = Vec::with_capacity(transition_inputs.len());
    let mut released_transition_sources = Vec::with_capacity(transition_inputs.len());
    for input in transition_inputs {
        let (mut arithmetic, mut range) = if let Some(scratch_directory) = scratch_directory {
            let arithmetic = prove_bls_dory_transition_deferred_at_variables_with_scratch(
                &component_binding,
                input.statement,
                input.mask_polynomial,
                input.witness,
                padded_variables,
                setup,
                scratch_directory,
            )?;
            let transition = arithmetic
                .openings
                .polynomial(0)
                .ok_or(BlsDorySharedLayoutError::OpeningClaims)?;
            let range = if input
                .statement
                .elements()
                .map_err(BlsDoryTransitionError::Structured)?
                >= BLS_DORY_RANGE_LOGUP_TABLE_VALUES
            {
                prove_bls_dory_range_logup_deferred_with_precommitted_compact_transition_and_scratch(
                    &component_binding,
                    input.statement,
                    transition,
                    padded_variables,
                    setup,
                    scratch_directory,
                )?
            } else {
                prove_bls_dory_range_logup_deferred_with_precommitted_transition_and_scratch(
                    &component_binding,
                    input.statement,
                    input.witness,
                    transition,
                    padded_variables,
                    setup,
                    scratch_directory,
                )?
            };
            (arithmetic, range)
        } else {
            (
                prove_bls_dory_transition_deferred_at_variables(
                    &component_binding,
                    input.statement,
                    input.mask_polynomial,
                    input.witness,
                    padded_variables,
                    setup,
                )?,
                prove_bls_dory_range_logup_deferred_at_variables(
                    &component_binding,
                    input.statement,
                    input.witness,
                    padded_variables,
                    setup,
                )?,
            )
        };
        if arithmetic.proof.oracle_commitment != range.proof.transition_commitment {
            return Err(BlsDorySharedLayoutError::TransitionRangeCommitment);
        }
        let released_source = if scratch_directory.is_some() {
            let arithmetic_source = arithmetic
                .openings
                .release_compact_source()?
                .ok_or(BlsDorySharedLayoutError::OpeningClaims)?;
            let range_source = range
                .openings
                .release_compact_source()?
                .ok_or(BlsDorySharedLayoutError::OpeningClaims)?;
            if arithmetic_source != range_source {
                return Err(BlsDorySharedLayoutError::OpeningClaims);
            }
            Some(arithmetic_source)
        } else {
            None
        };
        transitions.push((arithmetic, range));
        released_transition_sources.push(released_source);
    }
    let wiring = if let Some(scratch_directory) = scratch_directory {
        prove_bls_dory_wiring_deferred_at_variables_with_scratch(
            &component_binding,
            wiring_statement,
            initial,
            inputs,
            outputs,
            padded_variables,
            setup,
            scratch_directory,
        )?
    } else {
        prove_bls_dory_wiring_deferred_at_variables(
            &component_binding,
            wiring_statement,
            initial,
            inputs,
            outputs,
            padded_variables,
            setup,
        )?
    };
    if let Some(scratch_directory) = scratch_directory {
        let nu = padded_variables / 2;
        let sigma = padded_variables - nu;
        let rows = 1usize
            .checked_shl(
                u32::try_from(nu).map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)?,
            )
            .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
        let columns = 1usize
            .checked_shl(
                u32::try_from(sigma).map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)?,
            )
            .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
        for (((arithmetic, range), input), expected) in transitions
            .iter_mut()
            .zip(transition_inputs)
            .zip(&released_transition_sources)
        {
            let expected = expected
                .as_ref()
                .ok_or(BlsDorySharedLayoutError::OpeningClaims)?;
            let mut source = BlsDoryTransitionWitnessRowSource::new(
                input.statement,
                input.witness,
                rows,
                columns,
            )?;
            let restored = regenerate_bls_dory_compact_row_source_with_scratch(
                &mut source,
                expected,
                nu,
                sigma,
                setup,
                scratch_directory,
            )?;
            arithmetic.openings.restore_compact_source(&restored)?;
            range.openings.restore_compact_source(&restored)?;
        }
    }
    prepare_prepared_shared_layout(
        &component_binding,
        matrices,
        transitions,
        wiring,
        fixed_base,
        fixed_model,
        &matrix_statements,
        &transition_statements,
        wiring_statement,
        padded_variables,
        setup,
    )
}

#[allow(clippy::too_many_arguments)]
fn prepare_prepared_shared_layout(
    binding: &[u8],
    mut matrices: Vec<PreparedBlsDoryMatrixProof>,
    mut transitions: Vec<(
        PreparedBlsDoryTransitionProof,
        PreparedBlsDoryRangeLogUpProof,
    )>,
    mut wiring: PreparedBlsDoryWiringProof,
    fixed_base: BlsDoryCommittedPolynomial,
    fixed_model: &BlsDoryFixedModelIdentity,
    matrix_statements: &[StructuredMatrixStatement],
    transition_statements: &[StructuredTransitionStatement],
    wiring_statement: StructuredWiringStatement,
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<PreparedBlsDorySharedLayoutProverState, BlsDorySharedLayoutError> {
    let aggregate_layout = BlsDoryAggregateLayout::new(
        padded_variables / 2,
        padded_variables - padded_variables / 2,
    )?;
    let matrix_proofs = matrices
        .iter()
        .map(|prepared| &prepared.proof)
        .collect::<Vec<_>>();
    let transition_proofs = transitions
        .iter()
        .map(|(arithmetic, range)| (&arithmetic.proof, &range.proof))
        .collect::<Vec<_>>();
    let opening_binding = shared_opening_binding(
        binding,
        padded_variables,
        setup,
        &matrix_proofs,
        &transition_proofs,
        &wiring.proof,
        fixed_model,
    )?;
    let links = derive_shared_link_points(
        BLS_DORY_SHARED_LAYOUT_VERSION,
        &opening_binding,
        matrix_statements,
        transition_statements,
        wiring_statement,
        padded_variables,
    )?;
    let mut fixed_base = BlsDoryDeferredOpeningSet::unopened(vec![fixed_base])?;
    let link_evaluations = attach_prover_links(
        &links,
        &mut matrices,
        &mut transitions,
        &mut wiring,
        &mut fixed_base,
    )?;
    let final_output_points = derive_final_output_bridge_points(
        &opening_binding,
        transition_statements,
        wiring_statement,
        padded_variables,
    )?;
    let final_output_evaluation =
        attach_prover_final_output_bridge(&final_output_points, &mut transitions, &mut wiring)?;
    let mut opening_sets = Vec::new();
    let mut expected_claims = Vec::new();
    let mut matrix_proofs = Vec::with_capacity(matrices.len());
    for PreparedBlsDoryMatrixProof { proof, openings } in matrices {
        expected_claims.extend_from_slice(openings.claims());
        opening_sets.push(openings);
        matrix_proofs.push(proof);
    }
    let mut transition_proofs = Vec::with_capacity(transitions.len());
    for (arithmetic, range) in transitions {
        let PreparedBlsDoryTransitionProof {
            proof: arithmetic_proof,
            openings: arithmetic_openings,
        } = arithmetic;
        let PreparedBlsDoryRangeLogUpProof {
            proof: range_proof,
            openings: range_openings,
        } = range;
        expected_claims.extend_from_slice(arithmetic_openings.claims());
        opening_sets.push(arithmetic_openings);
        expected_claims.extend_from_slice(range_openings.claims());
        opening_sets.push(range_openings);
        transition_proofs.push(BlsDoryTransitionRangeProof {
            arithmetic: arithmetic_proof,
            range: range_proof,
        });
    }
    let PreparedBlsDoryWiringProof {
        proof: wiring_proof,
        openings: wiring_openings,
    } = wiring;
    expected_claims.extend_from_slice(wiring_openings.claims());
    opening_sets.push(wiring_openings);
    expected_claims.extend_from_slice(fixed_base.claims());
    opening_sets.push(fixed_base);
    Ok(PreparedBlsDorySharedLayoutProverState {
        aggregate_layout,
        shared_opening_binding: opening_binding,
        opening_sets,
        expected_claims,
        proof: BlsDorySharedLayoutProof {
            protocol_version: BLS_DORY_SHARED_LAYOUT_VERSION,
            padded_variables: u16::try_from(padded_variables)
                .map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)?,
            matrices: matrix_proofs,
            transitions: transition_proofs,
            wiring: wiring_proof,
            link_evaluations,
            final_output_evaluation,
            opening_proof: Vec::new(),
        },
        pending_final_output: PendingBlsDoryFinalOutputOpening {
            cell_point: final_output_points.cell_point,
            signed_evaluation: final_output_evaluation,
            transcript_binding: final_output_points.transcript_binding,
        },
    })
}

#[allow(clippy::too_many_arguments)]
#[allow(
    dead_code,
    reason = "used by the candidate-owned V3/V5 integration seam"
)]
fn prepare_prepared_shared_layout_v5(
    context: BlsDorySharedLayoutV5Context,
    component_binding: BlsDoryFixedModelBindingV2,
    matrices: Vec<PreparedBlsDoryMatrixProof>,
    transitions: Vec<(
        PreparedBlsDoryTransitionProof,
        PreparedBlsDoryRangeLogUpProof,
    )>,
    wiring: PreparedBlsDoryWiringProof,
    fixed_base: BlsDoryCommittedPolynomial,
    matrix_statements: &[StructuredMatrixStatement],
    transition_statements: &[StructuredTransitionStatement],
    wiring_statement: StructuredWiringStatement,
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<PreparedBlsDorySharedLayoutV5ProverState, BlsDorySharedLayoutError> {
    if validate_layout_v5_codec_context(&context)? != padded_variables
        || context.setup_identity != Digest32::new(setup.identity())
    {
        return Err(BlsDorySharedLayoutError::V3Context);
    }
    validate_layout_v5_production_statements(
        matrix_statements,
        transition_statements,
        wiring_statement,
    )?;
    let prepared = prepare_prepared_shared_layout_v5_validated(
        context,
        component_binding,
        matrices,
        transitions,
        wiring,
        fixed_base,
        matrix_statements,
        transition_statements,
        wiring_statement,
        padded_variables,
    )?;
    if prepared.expected_claims.len() != BLS_DORY_SHARED_PRODUCTION_CLAIMS {
        return Err(BlsDorySharedLayoutError::OpeningClaims);
    }
    Ok(prepared)
}

#[allow(clippy::too_many_arguments)]
fn prepare_prepared_shared_layout_v5_validated(
    context: BlsDorySharedLayoutV5Context,
    component_binding: BlsDoryFixedModelBindingV2,
    mut matrices: Vec<PreparedBlsDoryMatrixProof>,
    mut transitions: Vec<(
        PreparedBlsDoryTransitionProof,
        PreparedBlsDoryRangeLogUpProof,
    )>,
    mut wiring: PreparedBlsDoryWiringProof,
    fixed_base: BlsDoryCommittedPolynomial,
    matrix_statements: &[StructuredMatrixStatement],
    transition_statements: &[StructuredTransitionStatement],
    wiring_statement: StructuredWiringStatement,
    padded_variables: usize,
) -> Result<PreparedBlsDorySharedLayoutV5ProverState, BlsDorySharedLayoutError> {
    let aggregate_layout = BlsDoryAggregateLayout::new(
        padded_variables / 2,
        padded_variables - padded_variables / 2,
    )?;
    let matrix_proofs = matrices
        .iter()
        .map(|prepared| &prepared.proof)
        .collect::<Vec<_>>();
    let transition_proofs = transitions
        .iter()
        .map(|(arithmetic, range)| (&arithmetic.proof, &range.proof))
        .collect::<Vec<_>>();
    let opening_binding = context.shared_opening_binding(
        component_binding,
        &matrix_proofs,
        &transition_proofs,
        &wiring.proof,
    )?;
    let links = derive_shared_link_points(
        DORY_V3_SHARED_LAYOUT_VERSION,
        opening_binding.as_bytes(),
        matrix_statements,
        transition_statements,
        wiring_statement,
        padded_variables,
    )?;
    let mut fixed_base = BlsDoryDeferredOpeningSet::unopened(vec![fixed_base])?;
    let link_evaluations = attach_prover_links(
        &links,
        &mut matrices,
        &mut transitions,
        &mut wiring,
        &mut fixed_base,
    )?;
    let final_output_points = derive_final_output_bridge_points(
        opening_binding.as_bytes(),
        transition_statements,
        wiring_statement,
        padded_variables,
    )?;
    let final_output_evaluation =
        attach_prover_final_output_bridge(&final_output_points, &mut transitions, &mut wiring)?;

    let mut opening_sets = Vec::new();
    let mut expected_claims = Vec::new();
    let mut matrix_proofs = Vec::with_capacity(matrices.len());
    for PreparedBlsDoryMatrixProof { proof, openings } in matrices {
        expected_claims.extend_from_slice(openings.claims());
        opening_sets.push(openings);
        matrix_proofs.push(proof);
    }
    let mut transition_proofs = Vec::with_capacity(transitions.len());
    for (arithmetic, range) in transitions {
        let PreparedBlsDoryTransitionProof {
            proof: arithmetic_proof,
            openings: arithmetic_openings,
        } = arithmetic;
        let PreparedBlsDoryRangeLogUpProof {
            proof: range_proof,
            openings: range_openings,
        } = range;
        expected_claims.extend_from_slice(arithmetic_openings.claims());
        opening_sets.push(arithmetic_openings);
        expected_claims.extend_from_slice(range_openings.claims());
        opening_sets.push(range_openings);
        transition_proofs.push(BlsDoryTransitionRangeProof {
            arithmetic: arithmetic_proof,
            range: range_proof,
        });
    }
    let PreparedBlsDoryWiringProof {
        proof: wiring_proof,
        openings: wiring_openings,
    } = wiring;
    expected_claims.extend_from_slice(wiring_openings.claims());
    opening_sets.push(wiring_openings);
    expected_claims.extend_from_slice(fixed_base.claims());
    opening_sets.push(fixed_base);
    Ok(PreparedBlsDorySharedLayoutV5ProverState {
        context,
        aggregate_layout,
        shared_opening_binding: opening_binding,
        opening_sets,
        expected_claims,
        proof: BlsDorySharedLayoutProof {
            protocol_version: DORY_V3_SHARED_LAYOUT_VERSION,
            padded_variables: u16::try_from(padded_variables)
                .map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)?,
            matrices: matrix_proofs,
            transitions: transition_proofs,
            wiring: wiring_proof,
            link_evaluations,
            final_output_evaluation,
            opening_proof: Vec::new(),
        },
        pending_final_output: PendingBlsDoryFinalOutputOpening {
            cell_point: final_output_points.cell_point,
            signed_evaluation: final_output_evaluation,
            transcript_binding: final_output_points.transcript_binding,
        },
    })
}

fn finish_prepared_shared_layout(
    prepared: PreparedBlsDorySharedLayoutProverState,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: Option<&Path>,
) -> Result<BlsDorySharedLayoutProof, BlsDorySharedLayoutError> {
    let PreparedBlsDorySharedLayoutProverState {
        aggregate_layout,
        shared_opening_binding,
        opening_sets,
        expected_claims,
        mut proof,
        pending_final_output: _,
    } = prepared;
    let (claims, opening_proof) = if let Some(scratch_directory) = scratch_directory {
        prove_bls_dory_deferred_opening_sets_consuming_with_scratch(
            &shared_opening_binding,
            aggregate_layout,
            opening_sets,
            setup,
            scratch_directory,
        )?
    } else {
        prove_bls_dory_deferred_opening_sets_consuming(
            &shared_opening_binding,
            aggregate_layout,
            opening_sets,
            setup,
        )?
    };
    if claims != expected_claims {
        return Err(BlsDorySharedLayoutError::OpeningClaims);
    }
    proof.opening_proof = opening_proof;
    Ok(proof)
}

/// Test-only algebraic finish. Candidate construction must use the native-
/// composed 128+6 path and can never call this 128-claim helper.
#[cfg(test)]
#[allow(dead_code, reason = "reserved for bounded algebraic-only validation")]
fn finish_prepared_bls_dory_shared_layout_v5_algebraic_only_for_test(
    prepared: PreparedBlsDorySharedLayoutV5ProverState,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<BlsDorySharedLayoutV5Proof, BlsDorySharedLayoutError> {
    let PreparedBlsDorySharedLayoutV5ProverState {
        context,
        aggregate_layout,
        shared_opening_binding,
        opening_sets,
        expected_claims,
        mut proof,
        pending_final_output: _,
    } = prepared;
    let padded_variables = validate_layout_v5_codec_context(&context)?;
    if context.setup_identity != Digest32::new(setup.identity())
        || aggregate_layout
            != BlsDoryAggregateLayout::new(
                padded_variables / 2,
                padded_variables - padded_variables / 2,
            )?
        || expected_claims.len() != BLS_DORY_SHARED_PRODUCTION_CLAIMS
    {
        return Err(BlsDorySharedLayoutError::V3Context);
    }
    let (claims, opening_proof) = prove_bls_dory_deferred_opening_sets_consuming_with_scratch(
        shared_opening_binding.as_bytes(),
        aggregate_layout,
        opening_sets,
        setup,
        scratch_directory,
    )?;
    if claims != expected_claims {
        return Err(BlsDorySharedLayoutError::OpeningClaims);
    }
    proof.opening_proof = opening_proof;
    validate_shared_component_shape_v5(&proof, padded_variables)?;
    Ok(BlsDorySharedLayoutV5Proof { context, proof })
}

/// Produce the Dory-V3-domain native BLAKE3 argument, then append its exact six
/// openings after the canonical 128-claim Layout V5 prefix.
#[cfg(feature = "whir-prototype")]
#[allow(clippy::too_many_arguments)]
pub fn prove_prepared_bls_dory_shared_layout_v5_with_composition(
    prepared: PreparedBlsDorySharedLayoutV5ProverState,
    challenge_digest: [u8; 32],
    final_activation_digest: [u8; 32],
    final_activation: &[u8],
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
    maximum_native_block_rows: usize,
) -> Result<(BlsDorySharedLayoutV5Proof, Vec<u8>), BlsDorySharedLayoutError> {
    let padded_variables = validate_layout_v5_codec_context(&prepared.context)?;
    if prepared.context.setup_identity != Digest32::new(setup.identity())
        || prepared.aggregate_layout
            != BlsDoryAggregateLayout::new(
                padded_variables / 2,
                padded_variables - padded_variables / 2,
            )?
    {
        return Err(BlsDorySharedLayoutError::V3Context);
    }
    let bridge = BlsDoryOutputBridgeStatement::from_pending_dory(
        challenge_digest,
        final_activation_digest,
        final_activation.len(),
        prepared.pending_final_output(),
    )?;
    bridge.validate_activation(final_activation)?;
    let PreparedBlsDoryNativeBlake3Opening {
        opening_statement,
        opening_set,
        encoded_native_proof,
    } = prepare_production_dory_v3_native_blake3_opening(
        final_activation,
        &bridge,
        setup,
        scratch_directory,
        maximum_native_block_rows,
    )?;
    let native = BlsDorySharedLayoutV5NativeProverOpenings::from_deferred(
        opening_set,
        opening_statement.opening_binding(),
    )?;
    let proof = prove_prepared_bls_dory_shared_layout_v5_with_native_openings(
        prepared,
        native,
        setup,
        scratch_directory,
    )?;
    Ok((proof, encoded_native_proof))
}

#[cfg(any(test, feature = "whir-prototype"))]
#[allow(dead_code)]
fn prove_prepared_bls_dory_shared_layout_v5_with_native_openings(
    prepared: PreparedBlsDorySharedLayoutV5ProverState,
    native: BlsDorySharedLayoutV5NativeProverOpenings,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<BlsDorySharedLayoutV5Proof, BlsDorySharedLayoutError> {
    let BlsDorySharedLayoutV5NativeProverOpenings {
        openings: native_openings,
        opening_binding: native_opening_binding,
    } = native;
    let PreparedBlsDorySharedLayoutV5ProverState {
        context,
        aggregate_layout,
        shared_opening_binding,
        mut opening_sets,
        mut expected_claims,
        mut proof,
        pending_final_output: _,
    } = prepared;
    let padded_variables = validate_layout_v5_codec_context(&context)?;
    let expected_layout = BlsDoryAggregateLayout::new(
        padded_variables / 2,
        padded_variables - padded_variables / 2,
    )?;
    if context.setup_identity != Digest32::new(setup.identity())
        || aggregate_layout != expected_layout
    {
        return Err(BlsDorySharedLayoutError::OpeningClaims);
    }
    validate_layout_v5_composition_claim_counts(
        expected_claims.len(),
        native_openings.claims().len(),
    )?;
    let aggregate_binding = context.native_composition_binding(
        shared_opening_binding,
        native_opening_binding,
        aggregate_layout,
    )?;
    expected_claims.extend_from_slice(native_openings.claims());
    opening_sets.push(native_openings);
    if expected_claims.len() != BLS_DORY_BLAKE3_COMPOSED_OPENING_CLAIMS {
        return Err(BlsDorySharedLayoutError::OpeningClaims);
    }
    let (claims, opening_proof) = prove_bls_dory_deferred_opening_sets_consuming_composed(
        &aggregate_binding,
        aggregate_layout,
        opening_sets,
        setup,
        scratch_directory,
    )?;
    if claims != expected_claims {
        return Err(BlsDorySharedLayoutError::OpeningClaims);
    }
    proof.opening_proof = opening_proof;
    validate_shared_component_shape_v5(&proof, padded_variables)?;
    Ok(BlsDorySharedLayoutV5Proof { context, proof })
}

/// Append exactly the six native BLAKE3 claims after the canonical shared
/// prefix and authenticate all 134 claims with one test-only aggregate.
#[cfg(any(test, feature = "whir-prototype"))]
#[allow(dead_code)]
pub(crate) fn prove_prepared_bls_dory_shared_layout_with_composition(
    prepared: PreparedBlsDorySharedLayoutProverState,
    native_openings: BlsDoryDeferredOpeningSet,
    native_opening_binding: [u8; 32],
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<BlsDorySharedLayoutProof, BlsDorySharedLayoutError> {
    let PreparedBlsDorySharedLayoutProverState {
        aggregate_layout,
        shared_opening_binding,
        mut opening_sets,
        mut expected_claims,
        mut proof,
        pending_final_output: _,
    } = prepared;
    if expected_claims.len() != BLS_DORY_SHARED_PRODUCTION_CLAIMS
        || native_openings.claims().len() != BLS_DORY_SHARED_NATIVE_COMPOSITION_CLAIMS
        || native_opening_binding == [0; 32]
    {
        return Err(BlsDorySharedLayoutError::OpeningClaims);
    }
    expected_claims.extend_from_slice(native_openings.claims());
    opening_sets.push(native_openings);
    if expected_claims.len() != BLS_DORY_BLAKE3_COMPOSED_OPENING_CLAIMS {
        return Err(BlsDorySharedLayoutError::OpeningClaims);
    }
    let aggregate_binding = shared_native_composed_opening_binding(
        shared_opening_binding,
        native_opening_binding,
        aggregate_layout,
        setup,
    );
    let (claims, opening_proof) = prove_bls_dory_deferred_opening_sets_consuming_composed(
        &aggregate_binding,
        aggregate_layout,
        opening_sets,
        setup,
        scratch_directory,
    )?;
    if claims != expected_claims {
        return Err(BlsDorySharedLayoutError::OpeningClaims);
    }
    proof.opening_proof = opening_proof;
    Ok(proof)
}

/// Verify every component transcript, then authenticate their ordered opening
/// claims with exactly one Dory payload.
#[allow(clippy::too_many_arguments)]
pub fn verify_bls_dory_shared_layout_at_variables(
    binding: &[u8],
    trusted_model: &ModelPcsIdentity,
    fixed_model: &BlsDoryFixedModelIdentity,
    matrix_statements: &[StructuredMatrixStatement],
    transition_statements: &[StructuredTransitionStatement],
    mask_polynomials: &[&StructuredMaskPolynomial],
    wiring_statement: StructuredWiringStatement,
    proof: &BlsDorySharedLayoutProof,
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDorySharedLayoutError> {
    verify_bls_dory_shared_layout_with_final_output_at_variables(
        binding,
        trusted_model,
        fixed_model,
        matrix_statements,
        transition_statements,
        mask_polynomials,
        wiring_statement,
        proof,
        padded_variables,
        setup,
    )
    .map(|_| ())
}

/// Verify the shared layout and return the exact final-output opening needed by
/// the cross-field BLAKE3 bridge. This capability proves only the Dory side of
/// that bridge and is not sufficient for block admission.
#[allow(clippy::too_many_arguments)]
pub fn verify_bls_dory_shared_layout_with_final_output_at_variables(
    binding: &[u8],
    trusted_model: &ModelPcsIdentity,
    fixed_model: &BlsDoryFixedModelIdentity,
    matrix_statements: &[StructuredMatrixStatement],
    transition_statements: &[StructuredTransitionStatement],
    mask_polynomials: &[&StructuredMaskPolynomial],
    wiring_statement: StructuredWiringStatement,
    proof: &BlsDorySharedLayoutProof,
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<VerifiedBlsDoryFinalOutputOpening, BlsDorySharedLayoutError> {
    let prepared = prepare_bls_dory_shared_layout_verifier_state(
        binding,
        trusted_model,
        fixed_model,
        matrix_statements,
        transition_statements,
        mask_polynomials,
        wiring_statement,
        proof,
        padded_variables,
        setup,
    )?;
    let PreparedBlsDorySharedLayoutVerifierState {
        aggregate_layout,
        shared_opening_binding,
        claims,
        pending_final_output,
    } = prepared;
    verify_bls_dory_openings(
        &shared_opening_binding,
        aggregate_layout,
        &claims,
        &proof.opening_proof,
        setup,
    )?;
    Ok(pending_final_output.into_verified())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_bls_dory_shared_layout_verifier_state(
    binding: &[u8],
    trusted_model: &ModelPcsIdentity,
    fixed_model: &BlsDoryFixedModelIdentity,
    matrix_statements: &[StructuredMatrixStatement],
    transition_statements: &[StructuredTransitionStatement],
    mask_polynomials: &[&StructuredMaskPolynomial],
    wiring_statement: StructuredWiringStatement,
    proof: &BlsDorySharedLayoutProof,
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<PreparedBlsDorySharedLayoutVerifierState, BlsDorySharedLayoutError> {
    let aggregate_layout = BlsDoryAggregateLayout::new(
        padded_variables / 2,
        padded_variables - padded_variables / 2,
    )?;
    validate_shared_proof_shape(binding, proof, padded_variables)?;
    if proof.matrices.len() != matrix_statements.len()
        || proof.transitions.len() != transition_statements.len()
        || proof.transitions.len() != mask_polynomials.len()
    {
        return Err(BlsDorySharedLayoutError::InvalidProofShape);
    }
    validate_shared_link_topology(matrix_statements, transition_statements, wiring_statement)?;
    validate_fixed_model_topology(
        trusted_model,
        fixed_model,
        matrix_statements,
        transition_statements,
        wiring_statement,
        setup,
    )?;
    if proof
        .matrices
        .iter()
        .zip(&fixed_model.weight_bank_commitments)
        .any(|(matrix, commitment)| matrix.weight_commitment != *commitment)
    {
        return Err(BlsDorySharedLayoutError::FixedModelCommitment);
    }
    let component_binding = fixed_model_binding(binding, trusted_model, fixed_model, setup)?;
    let mut matrix_claims = Vec::with_capacity(proof.matrices.len());
    for (statement, matrix) in matrix_statements.iter().zip(&proof.matrices) {
        matrix_claims.push(verify_bls_dory_matrix_deferred_at_variables(
            &component_binding,
            *statement,
            matrix,
            padded_variables,
            setup,
        )?);
    }
    let mut transition_claims = Vec::with_capacity(proof.transitions.len());
    for ((statement, mask), transition) in transition_statements
        .iter()
        .zip(mask_polynomials)
        .zip(&proof.transitions)
    {
        if transition.arithmetic.oracle_commitment != transition.range.transition_commitment {
            return Err(BlsDorySharedLayoutError::TransitionRangeCommitment);
        }
        let arithmetic = verify_bls_dory_transition_deferred_at_variables(
            &component_binding,
            *statement,
            mask,
            &transition.arithmetic,
            padded_variables,
            setup,
        )?;
        let range = verify_bls_dory_range_logup_deferred_at_variables(
            &component_binding,
            *statement,
            transition.arithmetic.oracle_commitment,
            &transition.range,
            padded_variables,
            setup,
        )?;
        transition_claims.push((arithmetic, range));
    }
    let mut wiring_claims = verify_bls_dory_wiring_deferred_at_variables(
        &component_binding,
        wiring_statement,
        &proof.wiring,
        padded_variables,
        setup,
    )?;
    let matrix_proofs = proof.matrices.iter().collect::<Vec<_>>();
    let transition_proofs = proof
        .transitions
        .iter()
        .map(|proof| (&proof.arithmetic, &proof.range))
        .collect::<Vec<_>>();
    let opening_binding = shared_opening_binding(
        &component_binding,
        padded_variables,
        setup,
        &matrix_proofs,
        &transition_proofs,
        &proof.wiring,
        fixed_model,
    )?;
    let links = derive_shared_link_points(
        BLS_DORY_SHARED_LAYOUT_VERSION,
        &opening_binding,
        matrix_statements,
        transition_statements,
        wiring_statement,
        padded_variables,
    )?;
    let mut fixed_base_claims = Vec::with_capacity(1);
    attach_verifier_links(
        &links,
        &proof.link_evaluations,
        proof,
        fixed_model.base_input_commitment,
        &mut matrix_claims,
        &mut transition_claims,
        &mut wiring_claims,
        &mut fixed_base_claims,
    )?;
    let final_output_points = derive_final_output_bridge_points(
        &opening_binding,
        transition_statements,
        wiring_statement,
        padded_variables,
    )?;
    attach_verifier_final_output_bridge(
        &final_output_points,
        proof.final_output_evaluation,
        proof,
        &mut transition_claims,
        &mut wiring_claims,
    )?;
    let mut claims = Vec::new();
    for component in matrix_claims {
        claims.extend(component);
    }
    for (arithmetic, range) in transition_claims {
        claims.extend(arithmetic);
        claims.extend(range);
    }
    claims.extend(wiring_claims);
    claims.extend(fixed_base_claims);
    Ok(PreparedBlsDorySharedLayoutVerifierState {
        aggregate_layout,
        shared_opening_binding: opening_binding,
        claims,
        pending_final_output: PendingBlsDoryFinalOutputOpening {
            cell_point: final_output_points.cell_point,
            signed_evaluation: proof.final_output_evaluation,
            transcript_binding: final_output_points.transcript_binding,
        },
    })
}

/// Replay every exact production Layout V5 component against the commitments
/// in the same bank-authenticated Record V2 before accepting an aggregate.
#[allow(clippy::too_many_arguments)]
#[allow(
    dead_code,
    reason = "used by the candidate-owned V3/V5 integration seam"
)]
pub(crate) fn prepare_bls_dory_shared_layout_v5_verifier_state(
    binding: &[u8],
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    context: BlsDorySharedLayoutV5Context,
    component_binding: BlsDoryFixedModelBindingV2,
    matrix_statements: &[StructuredMatrixStatement],
    transition_statements: &[StructuredTransitionStatement],
    mask_polynomials: &[&StructuredMaskPolynomial],
    wiring_statement: StructuredWiringStatement,
    proof: &BlsDorySharedLayoutV5Proof,
    setup: &DeterministicBlsDorySetup,
) -> Result<PreparedBlsDorySharedLayoutV5VerifierState, BlsDorySharedLayoutError> {
    let padded_variables = validate_layout_v5_record_context_binding(
        binding,
        authenticated,
        context,
        component_binding,
        setup,
    )?;
    if proof.context != context {
        return Err(BlsDorySharedLayoutError::V3Context);
    }
    validate_layout_v5_production_statements(
        matrix_statements,
        transition_statements,
        wiring_statement,
    )?;
    if mask_polynomials.len() != MAX_BLS_DORY_SHARED_TRANSITION_PROOFS {
        return Err(BlsDorySharedLayoutError::InvalidProofShape);
    }
    validate_shared_component_shape_v5(&proof.proof, padded_variables)?;
    for (statement, mask) in transition_statements.iter().zip(mask_polynomials) {
        mask.validate(*statement)
            .map_err(BlsDoryTransitionError::from)?;
    }

    let model_identity = authenticated.record().model_identity();
    let expected_weights = model_identity.weight_bank_commitments();
    if expected_weights.len() != MAX_BLS_DORY_SHARED_MATRIX_PROOFS
        || proof
            .proof
            .matrices
            .iter()
            .zip(&expected_weights)
            .any(|(matrix, expected)| matrix.weight_commitment != *expected)
    {
        return Err(BlsDorySharedLayoutError::FixedModelCommitment);
    }
    if proof.proof.transitions.iter().any(|transition| {
        transition.arithmetic.oracle_commitment != transition.range.transition_commitment
    }) {
        return Err(BlsDorySharedLayoutError::TransitionRangeCommitment);
    }
    let aggregate_layout = BlsDoryAggregateLayout::new(
        padded_variables / 2,
        padded_variables - padded_variables / 2,
    )?;
    let mut matrix_claims = Vec::with_capacity(proof.proof.matrices.len());
    for (statement, matrix) in matrix_statements.iter().zip(&proof.proof.matrices) {
        matrix_claims.push(verify_bls_dory_matrix_deferred_at_variables(
            component_binding.as_bytes(),
            *statement,
            matrix,
            padded_variables,
            setup,
        )?);
    }
    let mut transition_claims = Vec::with_capacity(proof.proof.transitions.len());
    for ((statement, mask), transition) in transition_statements
        .iter()
        .zip(mask_polynomials)
        .zip(&proof.proof.transitions)
    {
        let arithmetic = verify_bls_dory_transition_deferred_at_variables(
            component_binding.as_bytes(),
            *statement,
            mask,
            &transition.arithmetic,
            padded_variables,
            setup,
        )?;
        let range = verify_bls_dory_range_logup_deferred_at_variables(
            component_binding.as_bytes(),
            *statement,
            transition.arithmetic.oracle_commitment,
            &transition.range,
            padded_variables,
            setup,
        )?;
        transition_claims.push((arithmetic, range));
    }
    let mut wiring_claims = verify_bls_dory_wiring_deferred_at_variables(
        component_binding.as_bytes(),
        wiring_statement,
        &proof.proof.wiring,
        padded_variables,
        setup,
    )?;
    let matrix_proofs = proof.proof.matrices.iter().collect::<Vec<_>>();
    let transition_proofs = proof
        .proof
        .transitions
        .iter()
        .map(|proof| (&proof.arithmetic, &proof.range))
        .collect::<Vec<_>>();
    let opening_binding = context.shared_opening_binding(
        component_binding,
        &matrix_proofs,
        &transition_proofs,
        &proof.proof.wiring,
    )?;
    let links = derive_shared_link_points(
        DORY_V3_SHARED_LAYOUT_VERSION,
        opening_binding.as_bytes(),
        matrix_statements,
        transition_statements,
        wiring_statement,
        padded_variables,
    )?;
    let mut fixed_base_claims = Vec::with_capacity(1);
    attach_verifier_links(
        &links,
        &proof.proof.link_evaluations,
        &proof.proof,
        model_identity.base_input_commitment(),
        &mut matrix_claims,
        &mut transition_claims,
        &mut wiring_claims,
        &mut fixed_base_claims,
    )?;
    let final_output_points = derive_final_output_bridge_points(
        opening_binding.as_bytes(),
        transition_statements,
        wiring_statement,
        padded_variables,
    )?;
    attach_verifier_final_output_bridge(
        &final_output_points,
        proof.proof.final_output_evaluation,
        &proof.proof,
        &mut transition_claims,
        &mut wiring_claims,
    )?;
    let mut claims = Vec::new();
    for component in matrix_claims {
        claims.extend(component);
    }
    for (arithmetic, range) in transition_claims {
        claims.extend(arithmetic);
        claims.extend(range);
    }
    claims.extend(wiring_claims);
    claims.extend(fixed_base_claims);
    if claims.len() != BLS_DORY_SHARED_PRODUCTION_CLAIMS {
        return Err(BlsDorySharedLayoutError::OpeningClaims);
    }
    Ok(PreparedBlsDorySharedLayoutV5VerifierState {
        context,
        aggregate_layout,
        shared_opening_binding: opening_binding,
        claims,
        opening_proof: proof.proof.opening_proof.clone(),
        pending_final_output: PendingBlsDoryFinalOutputOpening {
            cell_point: final_output_points.cell_point,
            signed_evaluation: proof.proof.final_output_evaluation,
            transcript_binding: final_output_points.transcript_binding,
        },
    })
}

/// Test-only split verifier phase. It validates every shared component and
/// reconstructs the canonical 128-claim prefix without accepting it yet.
#[cfg(test)]
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_bls_dory_shared_layout_verifier_state_for_test(
    binding: &[u8],
    trusted_model: &ModelPcsIdentity,
    fixed_model: &BlsDoryFixedModelIdentity,
    matrix_statements: &[StructuredMatrixStatement],
    transition_statements: &[StructuredTransitionStatement],
    mask_polynomials: &[&StructuredMaskPolynomial],
    wiring_statement: StructuredWiringStatement,
    proof: &BlsDorySharedLayoutProof,
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<PreparedBlsDorySharedLayoutVerifierState, BlsDorySharedLayoutError> {
    prepare_bls_dory_shared_layout_verifier_state(
        binding,
        trusted_model,
        fixed_model,
        matrix_statements,
        transition_statements,
        mask_polynomials,
        wiring_statement,
        proof,
        padded_variables,
        setup,
    )
}

/// Append exactly the six verifier-reconstructed native BLAKE3 claims after
/// the canonical shared prefix. The pending final-output opening is promoted
/// only after the one 134-claim aggregate verifies.
#[cfg(feature = "whir-prototype")]
#[allow(dead_code)]
pub(crate) fn verify_prepared_bls_dory_shared_layout_with_native_proof(
    prepared: PreparedBlsDorySharedLayoutVerifierState,
    challenge_digest: [u8; 32],
    final_activation_digest: [u8; 32],
    final_activation_len: usize,
    encoded_native_proof: &[u8],
    opening_proof: &[u8],
    setup: &DeterministicBlsDorySetup,
) -> Result<VerifiedBlsDoryFinalOutputOpening, BlsDorySharedLayoutError> {
    let bridge = BlsDoryOutputBridgeStatement::from_pending_dory(
        challenge_digest,
        final_activation_digest,
        final_activation_len,
        prepared.pending_final_output(),
    )?;
    let native_statement =
        verify_encoded_native_blake3_opening_statement(&bridge, encoded_native_proof, setup)?;
    verify_prepared_bls_dory_shared_layout_with_composition(
        prepared,
        native_statement,
        opening_proof,
        setup,
    )
}

/// Verify the six native BLAKE3 openings and the canonical 128-claim Layout V5
/// prefix under the context-owned native-composition binding.
#[cfg(feature = "whir-prototype")]
#[allow(clippy::too_many_arguments)]
pub fn verify_prepared_bls_dory_shared_layout_v5_with_native_proof(
    prepared: PreparedBlsDorySharedLayoutV5VerifierState,
    challenge_digest: [u8; 32],
    final_activation_digest: [u8; 32],
    final_activation_len: usize,
    encoded_native_proof: &[u8],
    setup: &DeterministicBlsDorySetup,
) -> Result<VerifiedBlsDoryFinalOutputOpening, BlsDorySharedLayoutError> {
    let padded_variables = validate_layout_v5_codec_context(&prepared.context)?;
    if prepared.context.setup_identity != Digest32::new(setup.identity())
        || prepared.aggregate_layout
            != BlsDoryAggregateLayout::new(
                padded_variables / 2,
                padded_variables - padded_variables / 2,
            )?
    {
        return Err(BlsDorySharedLayoutError::V3Context);
    }
    let bridge = BlsDoryOutputBridgeStatement::from_pending_dory(
        challenge_digest,
        final_activation_digest,
        final_activation_len,
        prepared.pending_final_output(),
    )?;
    let native_statement = verify_encoded_dory_v3_native_blake3_opening_statement(
        &bridge,
        encoded_native_proof,
        setup,
    )?;
    verify_prepared_bls_dory_shared_layout_v5_with_composition(prepared, native_statement, setup)
}

#[cfg(all(test, feature = "whir-prototype"))]
#[allow(clippy::too_many_arguments)]
fn verify_prepared_bls_dory_shared_layout_with_test_native_proof(
    prepared: PreparedBlsDorySharedLayoutVerifierState,
    challenge_digest: [u8; 32],
    final_activation_digest: [u8; 32],
    final_activation_len: usize,
    encoded_native_proof: &[u8],
    trusted_preprocessing_commitment: BlsDoryGt,
    opening_proof: &[u8],
    setup: &DeterministicBlsDorySetup,
) -> Result<VerifiedBlsDoryFinalOutputOpening, BlsDorySharedLayoutError> {
    let bridge = BlsDoryOutputBridgeStatement::from_pending_dory(
        challenge_digest,
        final_activation_digest,
        final_activation_len,
        prepared.pending_final_output(),
    )?;
    let native_statement = verify_encoded_native_blake3_test_opening_statement_at_layout(
        &bridge,
        encoded_native_proof,
        trusted_preprocessing_commitment,
        prepared.aggregate_layout,
        setup,
    )?;
    verify_prepared_bls_dory_shared_layout_with_composition(
        prepared,
        native_statement,
        opening_proof,
        setup,
    )
}

#[cfg(any(test, feature = "whir-prototype"))]
#[allow(dead_code)]
fn verify_prepared_bls_dory_shared_layout_with_composition(
    prepared: PreparedBlsDorySharedLayoutVerifierState,
    native_statement: BlsDoryBlake3OpeningStatement,
    opening_proof: &[u8],
    setup: &DeterministicBlsDorySetup,
) -> Result<VerifiedBlsDoryFinalOutputOpening, BlsDorySharedLayoutError> {
    let PreparedBlsDorySharedLayoutVerifierState {
        aggregate_layout,
        shared_opening_binding,
        mut claims,
        pending_final_output,
    } = prepared;
    let native_claims = native_statement.claims();
    let native_opening_binding = native_statement.opening_binding();
    if claims.len() != BLS_DORY_SHARED_PRODUCTION_CLAIMS
        || native_claims.len() != BLS_DORY_SHARED_NATIVE_COMPOSITION_CLAIMS
        || native_opening_binding == [0; 32]
    {
        return Err(BlsDorySharedLayoutError::OpeningClaims);
    }
    claims.extend(native_claims);
    if claims.len() != BLS_DORY_BLAKE3_COMPOSED_OPENING_CLAIMS {
        return Err(BlsDorySharedLayoutError::OpeningClaims);
    }
    let aggregate_binding = shared_native_composed_opening_binding(
        shared_opening_binding,
        native_opening_binding,
        aggregate_layout,
        setup,
    );
    verify_bls_dory_composed_openings(
        &aggregate_binding,
        aggregate_layout,
        &claims,
        opening_proof,
        setup,
    )?;
    Ok(pending_final_output.into_verified())
}

#[cfg(any(test, feature = "whir-prototype"))]
#[allow(dead_code)]
fn verify_prepared_bls_dory_shared_layout_v5_with_composition(
    prepared: PreparedBlsDorySharedLayoutV5VerifierState,
    native_statement: BlsDoryBlake3OpeningStatement,
    setup: &DeterministicBlsDorySetup,
) -> Result<VerifiedBlsDoryFinalOutputOpening, BlsDorySharedLayoutError> {
    let PreparedBlsDorySharedLayoutV5VerifierState {
        context,
        aggregate_layout,
        shared_opening_binding,
        mut claims,
        opening_proof,
        pending_final_output,
    } = prepared;
    let padded_variables = validate_layout_v5_codec_context(&context)?;
    let expected_layout = BlsDoryAggregateLayout::new(
        padded_variables / 2,
        padded_variables - padded_variables / 2,
    )?;
    let native_claims = native_statement.claims();
    let native_opening_binding = native_statement.opening_binding();
    if context.setup_identity != Digest32::new(setup.identity())
        || aggregate_layout != expected_layout
    {
        return Err(BlsDorySharedLayoutError::OpeningClaims);
    }
    validate_layout_v5_composition_claim_counts(claims.len(), native_claims.len())?;
    let aggregate_binding = context.native_composition_binding(
        shared_opening_binding,
        native_opening_binding,
        aggregate_layout,
    )?;
    claims.extend(native_claims);
    if claims.len() != BLS_DORY_BLAKE3_COMPOSED_OPENING_CLAIMS {
        return Err(BlsDorySharedLayoutError::OpeningClaims);
    }
    verify_bls_dory_composed_openings(
        &aggregate_binding,
        aggregate_layout,
        &claims,
        &opening_proof,
        setup,
    )?;
    Ok(pending_final_output.into_verified())
}

fn validate_shared_proof_shape(
    binding: &[u8],
    proof: &BlsDorySharedLayoutProof,
    padded_variables: usize,
) -> Result<(), BlsDorySharedLayoutError> {
    if binding.len() > MAX_SHARED_LAYOUT_BINDING_BYTES {
        return Err(BlsDorySharedLayoutError::InvalidProofShape);
    }
    validate_shared_component_shape(proof, padded_variables)
}

fn validate_shared_component_shape(
    proof: &BlsDorySharedLayoutProof,
    padded_variables: usize,
) -> Result<(), BlsDorySharedLayoutError> {
    if proof.protocol_version != BLS_DORY_SHARED_LAYOUT_VERSION
        || usize::from(proof.padded_variables) != padded_variables
        || proof.opening_proof.is_empty()
        || proof.opening_proof.len() > MAX_BLS_DORY_AGGREGATE_BYTES
        || !(1..=MAX_BLS_DORY_SHARED_MATRIX_PROOFS).contains(&proof.matrices.len())
        || !(1..=MAX_BLS_DORY_SHARED_TRANSITION_PROOFS).contains(&proof.transitions.len())
        || proof.transitions.len() != proof.matrices.len() + 1
        || proof.link_evaluations.len() != shared_link_count(proof.matrices.len())?
        || proof
            .matrices
            .iter()
            .any(|matrix| !matrix.opening_proof.is_empty())
        || proof.transitions.iter().any(|transition| {
            !transition.arithmetic.opening_proof.is_empty()
                || !transition.range.opening_proof.is_empty()
        })
        || !proof.wiring.opening_proof.is_empty()
    {
        return Err(BlsDorySharedLayoutError::InvalidProofShape);
    }
    Ok(())
}

fn append_serialized<T: DorySerialize>(
    output: &mut Vec<u8>,
    value: &T,
) -> Result<(), BlsDorySharedLayoutError> {
    value
        .serialize_compressed(output)
        .map_err(|_| BlsDorySharedLayoutError::InvalidEncoding)
}

fn read_serialized<T: DoryDeserialize>(
    reader: &mut Cursor<&[u8]>,
) -> Result<T, BlsDorySharedLayoutError> {
    T::deserialize_with_mode(reader, Compress::Yes, Validate::Yes)
        .map_err(|_| BlsDorySharedLayoutError::InvalidEncoding)
}

fn read_u16(encoded: &[u8], offset: usize) -> Result<u16, BlsDorySharedLayoutError> {
    let bytes = encoded
        .get(offset..offset + 2)
        .ok_or(BlsDorySharedLayoutError::InvalidEncoding)?;
    Ok(u16::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| BlsDorySharedLayoutError::InvalidEncoding)?,
    ))
}

fn read_u32(encoded: &[u8], offset: usize) -> Result<u32, BlsDorySharedLayoutError> {
    let bytes = encoded
        .get(offset..offset + 4)
        .ok_or(BlsDorySharedLayoutError::InvalidEncoding)?;
    Ok(u32::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| BlsDorySharedLayoutError::InvalidEncoding)?,
    ))
}

fn framed_size(total: usize, payload: usize) -> Result<usize, BlsDorySharedLayoutError> {
    total
        .checked_add(4)
        .and_then(|total| total.checked_add(payload))
        .ok_or(BlsDorySharedLayoutError::ProofTooLarge)
}

fn append_framed(encoded: &mut Vec<u8>, payload: &[u8]) -> Result<(), BlsDorySharedLayoutError> {
    let length =
        u32::try_from(payload.len()).map_err(|_| BlsDorySharedLayoutError::ProofTooLarge)?;
    encoded.extend_from_slice(&length.to_le_bytes());
    encoded.extend_from_slice(payload);
    Ok(())
}

fn take_framed<'a>(
    encoded: &'a [u8],
    offset: &mut usize,
) -> Result<&'a [u8], BlsDorySharedLayoutError> {
    let length = read_u32(encoded, *offset)? as usize;
    if length == 0 {
        return Err(BlsDorySharedLayoutError::InvalidProofShape);
    }
    *offset = offset
        .checked_add(4)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let end = offset
        .checked_add(length)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let payload = encoded
        .get(*offset..end)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    *offset = end;
    Ok(payload)
}

fn validate_fixed_model_topology(
    trusted_model: &ModelPcsIdentity,
    fixed_model: &BlsDoryFixedModelIdentity,
    matrices: &[StructuredMatrixStatement],
    transitions: &[StructuredTransitionStatement],
    wiring: StructuredWiringStatement,
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDorySharedLayoutError> {
    fixed_model.validate(trusted_model, matrices.len(), setup)?;
    if usize::try_from(trusted_model.batch).ok() != Some(wiring.rows)
        || usize::try_from(trusted_model.dimension).ok() != Some(wiring.cols)
        || usize::try_from(trusted_model.layers_per_bank).ok() != Some(wiring.layers_per_bank)
        || matrices.len() != trusted_model.weight_bank_commitments.len()
        || transitions.first().map(|statement| statement.layers) != Some(1)
    {
        return Err(BlsDorySharedLayoutError::FixedModelIdentity);
    }
    Ok(())
}

fn fixed_model_binding(
    binding: &[u8],
    trusted_model: &ModelPcsIdentity,
    fixed_model: &BlsDoryFixedModelIdentity,
    setup: &DeterministicBlsDorySetup,
) -> Result<[u8; 32], BlsDorySharedLayoutError> {
    if binding.len() > MAX_SHARED_LAYOUT_BINDING_BYTES {
        return Err(BlsDorySharedLayoutError::InvalidProofShape);
    }
    fixed_model.validate(
        trusted_model,
        fixed_model.weight_bank_commitments.len(),
        setup,
    )?;
    let binding_len =
        u32::try_from(binding.len()).map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)?;
    let mut hasher =
        blake3::Hasher::new_derive_key("CommonFoundry/ForgeMatrix/BlsDoryFixedModelBinding/v1");
    hasher.update(&binding_len.to_le_bytes());
    hasher.update(binding);
    hasher.update(
        &trusted_model
            .digest()
            .map_err(|_| BlsDorySharedLayoutError::FixedModelIdentity)?,
    );
    hasher.update(&fixed_model.digest()?);
    Ok(*hasher.finalize().as_bytes())
}

#[allow(clippy::too_many_arguments)]
fn shared_opening_binding(
    binding: &[u8],
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
    matrices: &[&BlsDoryMatrixProof],
    transitions: &[(&BlsDoryTransitionProof, &BlsDoryRangeLogUpProof)],
    wiring: &BlsDoryWiringProof,
    fixed_model: &BlsDoryFixedModelIdentity,
) -> Result<[u8; 32], BlsDorySharedLayoutError> {
    let variables =
        u16::try_from(padded_variables).map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)?;
    let binding_len =
        u32::try_from(binding.len()).map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CommonFoundry/BlsDorySharedLayout/openings/v1");
    hasher.update(&BLS_DORY_SHARED_LAYOUT_VERSION.to_le_bytes());
    hasher.update(&variables.to_le_bytes());
    hasher.update(&setup.identity());
    hasher.update(&binding_len.to_le_bytes());
    hasher.update(binding);
    hasher.update(&fixed_model.digest()?);
    hasher.update(&(matrices.len() as u16).to_le_bytes());
    for matrix in matrices {
        hasher.update(&matrix.transcript_digest);
    }
    hasher.update(&(transitions.len() as u16).to_le_bytes());
    for (arithmetic, range) in transitions {
        hasher.update(&arithmetic.transcript_digest);
        hasher.update(&range.transcript_digest);
    }
    hasher.update(&wiring.transcript_digest);
    Ok(*hasher.finalize().as_bytes())
}

#[cfg(any(test, feature = "whir-prototype"))]
fn shared_native_composed_opening_binding(
    shared_opening_binding: [u8; 32],
    native_opening_binding: [u8; 32],
    layout: BlsDoryAggregateLayout,
    setup: &DeterministicBlsDorySetup,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(
        "CommonFoundry/ForgeMatrix/BlsDorySharedNativeAggregateBinding/v1",
    );
    hasher.update(&BLS_DORY_SHARED_NATIVE_COMPOSITION_VERSION.to_le_bytes());
    hasher.update(&BLS_DORY_AGGREGATE_VERSION.to_le_bytes());
    hasher.update(&BLS_DORY_SHARED_LAYOUT_VERSION.to_le_bytes());
    hasher.update(&BLS_DORY_BLAKE3_PROJECTION_VERSION.to_le_bytes());
    hasher.update(&setup.identity());
    hasher.update(&(setup.max_log_n() as u64).to_le_bytes());
    hasher.update(&(layout.nu() as u64).to_le_bytes());
    hasher.update(&(layout.sigma() as u64).to_le_bytes());
    hasher.update(&(layout.variables() as u64).to_le_bytes());
    hasher.update(&(BLS_DORY_SHARED_PRODUCTION_CLAIMS as u64).to_le_bytes());
    hasher.update(&(BLS_DORY_SHARED_NATIVE_COMPOSITION_CLAIMS as u64).to_le_bytes());
    hasher.update(&(BLS_DORY_BLAKE3_COMPOSED_OPENING_CLAIMS as u64).to_le_bytes());
    hasher.update(b"shared-prefix");
    hasher.update(&shared_opening_binding);
    hasher.update(b"native-suffix");
    hasher.update(&native_opening_binding);
    *hasher.finalize().as_bytes()
}

#[derive(Clone, Copy)]
enum SharedLinkRole {
    FixedBaseInput,
    MatrixActivation(usize),
    MatrixAccumulator(usize),
    TransitionInput(usize),
    TransitionActivation(usize),
    WiringInitial,
    WiringInput,
    WiringOutput,
}

struct SharedEqualityLink {
    left: SharedLinkRole,
    left_point: Vec<BlsDoryFr>,
    right: SharedLinkRole,
    right_point: Vec<BlsDoryFr>,
}

fn shared_link_count(banks: usize) -> Result<usize, BlsDorySharedLayoutError> {
    BLS_DORY_SHARED_LINKS_PER_BANK
        .checked_mul(banks)
        .and_then(|count| count.checked_add(BLS_DORY_SHARED_INITIALIZATION_LINKS))
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)
}

fn validate_shared_link_topology(
    matrices: &[StructuredMatrixStatement],
    transitions: &[StructuredTransitionStatement],
    wiring: StructuredWiringStatement,
) -> Result<(), BlsDorySharedLayoutError> {
    if matrices.len() != wiring.banks
        || transitions.len() != matrices.len() + 1
        || transitions[0].layers != 1
        || transitions[0].rows != wiring.rows
        || transitions[0].cols != wiring.cols
    {
        return Err(BlsDorySharedLayoutError::LinkTopology);
    }
    for (matrix, transition) in matrices.iter().zip(&transitions[1..]) {
        if matrix.layers != wiring.layers_per_bank
            || matrix.rows != wiring.rows
            || matrix.inner != wiring.cols
            || matrix.cols != wiring.cols
            || transition.layers != matrix.layers
            || transition.rows != matrix.rows
            || transition.cols != matrix.cols
        {
            return Err(BlsDorySharedLayoutError::LinkTopology);
        }
    }
    Ok(())
}

fn derive_shared_link_points(
    protocol_version: u16,
    opening_binding: &[u8; 32],
    matrices: &[StructuredMatrixStatement],
    transitions: &[StructuredTransitionStatement],
    wiring: StructuredWiringStatement,
    padded_variables: usize,
) -> Result<Vec<SharedEqualityLink>, BlsDorySharedLayoutError> {
    if protocol_version != BLS_DORY_SHARED_LAYOUT_VERSION
        && protocol_version != DORY_V3_SHARED_LAYOUT_VERSION
    {
        return Err(BlsDorySharedLayoutError::InvalidProofShape);
    }
    validate_shared_link_topology(matrices, transitions, wiring)?;
    let mut transcript = BlsDoryTranscript::new(b"shared-equality-links");
    transcript.append_bytes(b"protocol-version", &protocol_version.to_le_bytes());
    transcript.append_bytes(b"opening-binding", opening_binding);
    transcript.append_bytes(b"matrix-count", &(matrices.len() as u64).to_le_bytes());
    transcript.append_bytes(
        b"transition-count",
        &(transitions.len() as u64).to_le_bytes(),
    );

    let initialization_variables = transitions[0]
        .elements()
        .map_err(BlsDoryTransitionError::from)?
        .ilog2() as usize;
    let base_point = link_challenge_point(&mut transcript, 0, initialization_variables);
    let mut links = Vec::with_capacity(shared_link_count(matrices.len())?);
    links.push(SharedEqualityLink {
        left: SharedLinkRole::TransitionInput(0),
        left_point: packed_link_point(
            &base_point,
            STRUCTURED_TRANSITION_INPUT_ORACLE,
            7,
            padded_variables,
        )?,
        right: SharedLinkRole::FixedBaseInput,
        right_point: pad_link_point(&base_point, padded_variables)?,
    });

    let initial_point = link_challenge_point(&mut transcript, 1, initialization_variables);
    let mut wiring_initial_point = initial_point.clone();
    wiring_initial_point.resize(
        initialization_variables + wiring.layers_per_bank.ilog2() as usize,
        BlsDoryFr::zero(),
    );
    links.push(SharedEqualityLink {
        left: SharedLinkRole::TransitionActivation(0),
        left_point: packed_link_point(
            &initial_point,
            STRUCTURED_TRANSITION_ACTIVATION_ORACLE,
            7,
            padded_variables,
        )?,
        right: SharedLinkRole::WiringInitial,
        right_point: packed_link_point(&wiring_initial_point, 0, 3, padded_variables)?,
    });

    for (bank, transition) in transitions[1..].iter().enumerate() {
        let table_variables = transition
            .elements()
            .map_err(BlsDoryTransitionError::from)?
            .ilog2() as usize;
        for relation in 0..BLS_DORY_SHARED_LINKS_PER_BANK {
            let link_index = BLS_DORY_SHARED_INITIALIZATION_LINKS
                + bank * BLS_DORY_SHARED_LINKS_PER_BANK
                + relation;
            let point = link_challenge_point(&mut transcript, link_index, table_variables);
            let direct_point = pad_link_point(&point, padded_variables)?;
            let transition_index = bank + 1;
            let link = match relation {
                0 => SharedEqualityLink {
                    left: SharedLinkRole::MatrixActivation(bank),
                    left_point: direct_point,
                    right: SharedLinkRole::WiringInput,
                    right_point: packed_link_point(&point, 1 + bank * 2, 3, padded_variables)?,
                },
                1 => SharedEqualityLink {
                    left: SharedLinkRole::MatrixAccumulator(bank),
                    left_point: direct_point,
                    right: SharedLinkRole::TransitionInput(transition_index),
                    right_point: packed_link_point(
                        &point,
                        STRUCTURED_TRANSITION_INPUT_ORACLE,
                        7,
                        padded_variables,
                    )?,
                },
                2 => SharedEqualityLink {
                    left: SharedLinkRole::TransitionActivation(transition_index),
                    left_point: packed_link_point(
                        &point,
                        STRUCTURED_TRANSITION_ACTIVATION_ORACLE,
                        7,
                        padded_variables,
                    )?,
                    right: SharedLinkRole::WiringOutput,
                    right_point: packed_link_point(&point, 2 + bank * 2, 3, padded_variables)?,
                },
                _ => return Err(BlsDorySharedLayoutError::InvalidProofShape),
            };
            links.push(link);
        }
    }
    Ok(links)
}

fn link_challenge_point(
    transcript: &mut BlsDoryTranscript,
    link_index: usize,
    variables: usize,
) -> Vec<BlsDoryFr> {
    transcript.append_bytes(b"link-index", &(link_index as u64).to_le_bytes());
    transcript.append_bytes(b"link-variables", &(variables as u64).to_le_bytes());
    (0..variables)
        .map(|coordinate| {
            transcript.append_bytes(b"coordinate", &(coordinate as u64).to_le_bytes());
            transcript.challenge_scalar(b"link-point")
        })
        .collect()
}

fn packed_link_point(
    table_point: &[BlsDoryFr],
    slot: usize,
    selector_variables: usize,
    padded_variables: usize,
) -> Result<Vec<BlsDoryFr>, BlsDorySharedLayoutError> {
    let mut point = Vec::with_capacity(padded_variables);
    point.extend_from_slice(table_point);
    for bit in 0..selector_variables {
        point.push(if (slot >> bit) & 1 == 0 {
            BlsDoryFr::zero()
        } else {
            BlsDoryFr::one()
        });
    }
    pad_link_point(&point, padded_variables)
}

fn pad_link_point(
    point: &[BlsDoryFr],
    padded_variables: usize,
) -> Result<Vec<BlsDoryFr>, BlsDorySharedLayoutError> {
    if point.len() > padded_variables {
        return Err(BlsDorySharedLayoutError::InvalidProofShape);
    }
    let mut padded = Vec::with_capacity(padded_variables);
    padded.extend_from_slice(point);
    padded.resize(padded_variables, BlsDoryFr::zero());
    Ok(padded)
}

struct FinalOutputBridgePoints {
    cell_point: Vec<BlsDoryFr>,
    transition_point: Vec<BlsDoryFr>,
    wiring_point: Vec<BlsDoryFr>,
    transcript_binding: [u8; 32],
}

fn derive_final_output_bridge_points(
    opening_binding: &[u8; 32],
    transitions: &[StructuredTransitionStatement],
    wiring: StructuredWiringStatement,
    padded_variables: usize,
) -> Result<FinalOutputBridgePoints, BlsDorySharedLayoutError> {
    let final_transition = transitions
        .last()
        .ok_or(BlsDorySharedLayoutError::LinkTopology)?;
    let cells = wiring
        .rows
        .checked_mul(wiring.cols)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    if cells == 0
        || !cells.is_power_of_two()
        || !wiring.layers_per_bank.is_power_of_two()
        || final_transition.rows != wiring.rows
        || final_transition.cols != wiring.cols
        || final_transition.layers != wiring.layers_per_bank
    {
        return Err(BlsDorySharedLayoutError::LinkTopology);
    }
    let cell_variables = cells.ilog2() as usize;
    let layer_variables = wiring.layers_per_bank.ilog2() as usize;
    let mut transcript = BlsDoryTranscript::new(b"shared-final-output-bridge");
    transcript.append_bytes(
        b"bridge-version",
        &BLS_DORY_FINAL_OUTPUT_BRIDGE_VERSION.to_le_bytes(),
    );
    transcript.append_bytes(b"opening-binding", opening_binding);
    transcript.append_bytes(b"rows", &(wiring.rows as u64).to_le_bytes());
    transcript.append_bytes(b"cols", &(wiring.cols as u64).to_le_bytes());
    transcript.append_bytes(
        b"layers-per-bank",
        &(wiring.layers_per_bank as u64).to_le_bytes(),
    );
    transcript.append_bytes(b"banks", &(wiring.banks as u64).to_le_bytes());
    let cell_point = (0..cell_variables)
        .map(|coordinate| {
            transcript.append_bytes(b"coordinate", &(coordinate as u64).to_le_bytes());
            transcript.challenge_scalar(b"final-output-cell-point")
        })
        .collect::<Vec<_>>();
    let transcript_binding = transcript.digest();

    let mut table_point = cell_point.clone();
    table_point.resize(cell_variables + layer_variables, BlsDoryFr::one());
    let transition_point = packed_link_point(
        &table_point,
        STRUCTURED_TRANSITION_ACTIVATION_ORACLE,
        7,
        padded_variables,
    )?;
    let final_wiring_output_slot = wiring
        .banks
        .checked_sub(1)
        .and_then(|bank| bank.checked_mul(2))
        .and_then(|slot| slot.checked_add(2))
        .ok_or(BlsDorySharedLayoutError::LinkTopology)?;
    let wiring_point =
        packed_link_point(&table_point, final_wiring_output_slot, 3, padded_variables)?;
    Ok(FinalOutputBridgePoints {
        cell_point,
        transition_point,
        wiring_point,
        transcript_binding,
    })
}

fn attach_prover_final_output_bridge(
    points: &FinalOutputBridgePoints,
    transitions: &mut [(
        PreparedBlsDoryTransitionProof,
        PreparedBlsDoryRangeLogUpProof,
    )],
    wiring: &mut PreparedBlsDoryWiringProof,
) -> Result<BlsDoryFr, BlsDorySharedLayoutError> {
    let transition = transitions
        .last_mut()
        .ok_or(BlsDorySharedLayoutError::LinkTopology)?
        .0
        .openings
        .push_opening(0, points.transition_point.clone())?;
    let wiring = wiring
        .openings
        .push_opening(0, points.wiring_point.clone())?;
    if transition.evaluation != wiring.evaluation {
        return Err(BlsDorySharedLayoutError::LinkEvaluation);
    }
    Ok(transition.evaluation)
}

#[allow(clippy::too_many_arguments)]
fn attach_verifier_final_output_bridge(
    points: &FinalOutputBridgePoints,
    evaluation: BlsDoryFr,
    proof: &BlsDorySharedLayoutProof,
    transitions: &mut [(Vec<BlsDoryOpeningClaim>, Vec<BlsDoryOpeningClaim>)],
    wiring: &mut Vec<BlsDoryOpeningClaim>,
) -> Result<(), BlsDorySharedLayoutError> {
    let transition_commitment = proof
        .transitions
        .last()
        .ok_or(BlsDorySharedLayoutError::LinkTopology)?
        .arithmetic
        .oracle_commitment;
    let transition_claims = transitions
        .last_mut()
        .ok_or(BlsDorySharedLayoutError::LinkTopology)?;
    transition_claims.0.push(BlsDoryOpeningClaim {
        commitment: transition_commitment,
        point: points.transition_point.clone(),
        evaluation,
    });
    wiring.push(BlsDoryOpeningClaim {
        commitment: proof.wiring.oracle_commitment,
        point: points.wiring_point.clone(),
        evaluation,
    });
    Ok(())
}

fn attach_prover_links(
    links: &[SharedEqualityLink],
    matrices: &mut [PreparedBlsDoryMatrixProof],
    transitions: &mut [(
        PreparedBlsDoryTransitionProof,
        PreparedBlsDoryRangeLogUpProof,
    )],
    wiring: &mut PreparedBlsDoryWiringProof,
    fixed_base: &mut BlsDoryDeferredOpeningSet,
) -> Result<Vec<BlsDoryFr>, BlsDorySharedLayoutError> {
    let mut evaluations = Vec::with_capacity(links.len());
    for link in links {
        let left = push_prover_role_opening(
            link.left,
            link.left_point.clone(),
            matrices,
            transitions,
            wiring,
            fixed_base,
        )?;
        let right = push_prover_role_opening(
            link.right,
            link.right_point.clone(),
            matrices,
            transitions,
            wiring,
            fixed_base,
        )?;
        if left.evaluation != right.evaluation {
            return Err(BlsDorySharedLayoutError::LinkEvaluation);
        }
        evaluations.push(left.evaluation);
    }
    Ok(evaluations)
}

fn push_prover_role_opening(
    role: SharedLinkRole,
    point: Vec<BlsDoryFr>,
    matrices: &mut [PreparedBlsDoryMatrixProof],
    transitions: &mut [(
        PreparedBlsDoryTransitionProof,
        PreparedBlsDoryRangeLogUpProof,
    )],
    wiring: &mut PreparedBlsDoryWiringProof,
    fixed_base: &mut BlsDoryDeferredOpeningSet,
) -> Result<BlsDoryOpeningClaim, BlsDorySharedLayoutError> {
    Ok(match role {
        SharedLinkRole::FixedBaseInput => fixed_base.push_opening(0, point)?,
        SharedLinkRole::MatrixActivation(bank) => matrices
            .get_mut(bank)
            .ok_or(BlsDorySharedLayoutError::LinkTopology)?
            .openings
            .push_opening(0, point)?,
        SharedLinkRole::MatrixAccumulator(bank) => matrices
            .get_mut(bank)
            .ok_or(BlsDorySharedLayoutError::LinkTopology)?
            .openings
            .push_opening(2, point)?,
        SharedLinkRole::TransitionInput(index) | SharedLinkRole::TransitionActivation(index) => {
            transitions
                .get_mut(index)
                .ok_or(BlsDorySharedLayoutError::LinkTopology)?
                .0
                .openings
                .push_opening(0, point)?
        }
        SharedLinkRole::WiringInitial
        | SharedLinkRole::WiringInput
        | SharedLinkRole::WiringOutput => wiring.openings.push_opening(0, point)?,
    })
}

#[allow(clippy::too_many_arguments)]
fn attach_verifier_links(
    links: &[SharedEqualityLink],
    evaluations: &[BlsDoryFr],
    proof: &BlsDorySharedLayoutProof,
    fixed_base_commitment: BlsDoryGt,
    matrices: &mut [Vec<BlsDoryOpeningClaim>],
    transitions: &mut [(Vec<BlsDoryOpeningClaim>, Vec<BlsDoryOpeningClaim>)],
    wiring: &mut Vec<BlsDoryOpeningClaim>,
    fixed_base: &mut Vec<BlsDoryOpeningClaim>,
) -> Result<(), BlsDorySharedLayoutError> {
    if links.len() != evaluations.len() {
        return Err(BlsDorySharedLayoutError::InvalidProofShape);
    }
    for (link, evaluation) in links.iter().zip(evaluations) {
        push_verifier_role_claim(
            link.left,
            link.left_point.clone(),
            *evaluation,
            proof,
            fixed_base_commitment,
            matrices,
            transitions,
            wiring,
            fixed_base,
        )?;
        push_verifier_role_claim(
            link.right,
            link.right_point.clone(),
            *evaluation,
            proof,
            fixed_base_commitment,
            matrices,
            transitions,
            wiring,
            fixed_base,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn push_verifier_role_claim(
    role: SharedLinkRole,
    point: Vec<BlsDoryFr>,
    evaluation: BlsDoryFr,
    proof: &BlsDorySharedLayoutProof,
    fixed_base_commitment: BlsDoryGt,
    matrices: &mut [Vec<BlsDoryOpeningClaim>],
    transitions: &mut [(Vec<BlsDoryOpeningClaim>, Vec<BlsDoryOpeningClaim>)],
    wiring: &mut Vec<BlsDoryOpeningClaim>,
    fixed_base: &mut Vec<BlsDoryOpeningClaim>,
) -> Result<(), BlsDorySharedLayoutError> {
    let commitment = role_commitment(role, proof, fixed_base_commitment)?;
    let claim = BlsDoryOpeningClaim {
        commitment,
        point,
        evaluation,
    };
    match role {
        SharedLinkRole::FixedBaseInput => fixed_base.push(claim),
        SharedLinkRole::MatrixActivation(bank) | SharedLinkRole::MatrixAccumulator(bank) => {
            matrices
                .get_mut(bank)
                .ok_or(BlsDorySharedLayoutError::LinkTopology)?
                .push(claim)
        }
        SharedLinkRole::TransitionInput(index) | SharedLinkRole::TransitionActivation(index) => {
            transitions
                .get_mut(index)
                .ok_or(BlsDorySharedLayoutError::LinkTopology)?
                .0
                .push(claim)
        }
        SharedLinkRole::WiringInitial
        | SharedLinkRole::WiringInput
        | SharedLinkRole::WiringOutput => wiring.push(claim),
    }
    Ok(())
}

fn role_commitment(
    role: SharedLinkRole,
    proof: &BlsDorySharedLayoutProof,
    fixed_base_commitment: BlsDoryGt,
) -> Result<BlsDoryGt, BlsDorySharedLayoutError> {
    Ok(match role {
        SharedLinkRole::FixedBaseInput => fixed_base_commitment,
        SharedLinkRole::MatrixActivation(bank) => {
            proof
                .matrices
                .get(bank)
                .ok_or(BlsDorySharedLayoutError::LinkTopology)?
                .activation_commitment
        }
        SharedLinkRole::MatrixAccumulator(bank) => {
            proof
                .matrices
                .get(bank)
                .ok_or(BlsDorySharedLayoutError::LinkTopology)?
                .accumulator_commitment
        }
        SharedLinkRole::TransitionInput(index) | SharedLinkRole::TransitionActivation(index) => {
            proof
                .transitions
                .get(index)
                .ok_or(BlsDorySharedLayoutError::LinkTopology)?
                .arithmetic
                .oracle_commitment
        }
        SharedLinkRole::WiringInitial
        | SharedLinkRole::WiringInput
        | SharedLinkRole::WiringOutput => proof.wiring.oracle_commitment,
    })
}

/// Prove transition arithmetic and range constraints against one commitment.
pub fn prove_bls_dory_transition_range(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    witness: &StructuredTransitionWitness,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryTransitionRangeProof, BlsDorySharedLayoutError> {
    let arithmetic =
        prove_bls_dory_transition(binding, statement, mask_polynomial, witness, setup)?;
    let range = prove_bls_dory_range_logup(binding, statement, witness, setup)?;
    transition_range_proof(arithmetic, range)
}

/// Prove the combined transition checkpoint at an exact shared geometry.
pub fn prove_bls_dory_transition_range_at_variables(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    witness: &StructuredTransitionWitness,
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryTransitionRangeProof, BlsDorySharedLayoutError> {
    let arithmetic = prove_bls_dory_transition_at_variables(
        binding,
        statement,
        mask_polynomial,
        witness,
        packed_variables,
        setup,
    )?;
    let range = prove_bls_dory_range_logup_at_variables(
        binding,
        statement,
        witness,
        packed_variables,
        setup,
    )?;
    transition_range_proof(arithmetic, range)
}

fn transition_range_proof(
    arithmetic: BlsDoryTransitionProof,
    range: BlsDoryRangeLogUpProof,
) -> Result<BlsDoryTransitionRangeProof, BlsDorySharedLayoutError> {
    if arithmetic.oracle_commitment != range.transition_commitment {
        return Err(BlsDorySharedLayoutError::TransitionRangeCommitment);
    }
    Ok(BlsDoryTransitionRangeProof { arithmetic, range })
}

/// Verify both halves of the transition relation against one commitment.
pub fn verify_bls_dory_transition_range(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    proof: &BlsDoryTransitionRangeProof,
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDorySharedLayoutError> {
    if proof.arithmetic.oracle_commitment != proof.range.transition_commitment {
        return Err(BlsDorySharedLayoutError::TransitionRangeCommitment);
    }
    verify_bls_dory_transition(
        binding,
        statement,
        mask_polynomial,
        &proof.arithmetic,
        setup,
    )?;
    verify_bls_dory_range_logup(
        binding,
        statement,
        proof.arithmetic.oracle_commitment,
        &proof.range,
        setup,
    )?;
    Ok(())
}

/// Verify the combined transition checkpoint at an exact shared geometry.
pub fn verify_bls_dory_transition_range_at_variables(
    binding: &[u8],
    statement: StructuredTransitionStatement,
    mask_polynomial: &StructuredMaskPolynomial,
    proof: &BlsDoryTransitionRangeProof,
    packed_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDorySharedLayoutError> {
    if proof.arithmetic.oracle_commitment != proof.range.transition_commitment {
        return Err(BlsDorySharedLayoutError::TransitionRangeCommitment);
    }
    verify_bls_dory_transition_at_variables(
        binding,
        statement,
        mask_polynomial,
        &proof.arithmetic,
        packed_variables,
        setup,
    )?;
    verify_bls_dory_range_logup_at_variables(
        binding,
        statement,
        proof.arithmetic.oracle_commitment,
        &proof.range,
        packed_variables,
        setup,
    )?;
    Ok(())
}

fn projected_shared_scalar_artifact_bytes(
    logical_scalars: u64,
    explicit_scalars: u64,
    generation: u32,
) -> Result<u64, BlsDorySharedLayoutError> {
    BlsDoryFoldArtifactSpec {
        context_digest: [1; 32],
        table_index: 0,
        generation,
        scalar_count: logical_scalars,
        explicit_scalar_count: explicit_scalars,
        parent_digest: [2; 32],
    }
    .encoded_bytes()
    .map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)
}

fn projected_shared_signed_word_source_bytes(
    logical_scalars: u64,
    explicit_scalars: u64,
    word_group_len: u64,
) -> Result<u64, BlsDorySharedLayoutError> {
    BlsDoryCompactArtifactSpec {
        context_digest: [1; 32],
        scalar_count: logical_scalars,
        explicit_scalar_count: explicit_scalars,
        word_scalar_count: explicit_scalars,
        word_bytes: 8,
        code_bits: 8,
        word_width_codes: 0,
        word_group_len,
        signed_word_selectors: 1,
    }
    .encoded_bytes(1)
    .map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)
}

fn projected_shared_signed_byte_source_bytes(
    logical_scalars: u64,
    explicit_scalars: u64,
    row_scalars: u64,
    maximum: u8,
) -> Result<u64, BlsDorySharedLayoutError> {
    let dictionary_len = usize::from(maximum)
        .checked_mul(2)
        .and_then(|value| value.checked_add(1))
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    BlsDoryCompactArtifactSpec {
        context_digest: [1; 32],
        scalar_count: logical_scalars,
        explicit_scalar_count: explicit_scalars,
        word_scalar_count: explicit_scalars.min(row_scalars),
        word_bytes: 8,
        code_bits: 8,
        word_width_codes: 0,
        word_group_len: explicit_scalars.min(row_scalars),
        signed_word_selectors: 1,
    }
    .encoded_bytes(dictionary_len)
    .map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)
}

fn projected_shared_transition_source_bytes(
    logical_scalars: u64,
    cells: u64,
) -> Result<u64, BlsDorySharedLayoutError> {
    let explicit_scalars = cells
        .checked_mul(STRUCTURED_TRANSITION_ORACLES as u64)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let word_scalars = cells
        .checked_mul(STRUCTURED_TRANSITION_REGULAR_ORACLES as u64)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    BlsDoryCompactArtifactSpec {
        context_digest: [1; 32],
        scalar_count: logical_scalars,
        explicit_scalar_count: explicit_scalars,
        word_scalar_count: word_scalars,
        word_bytes: 4,
        code_bits: 4,
        word_width_codes: PRODUCTION_TRANSITION_WORD_WIDTH_CODES,
        word_group_len: cells,
        signed_word_selectors: TRANSITION_SIGNED_WORD_SELECTORS,
    }
    .encoded_bytes(BLS_DORY_RANGE_LOGUP_TABLE_VALUES)
    .map_err(|_| BlsDorySharedLayoutError::InvalidProofShape)
}

fn checked_projection_sum(values: &[u64]) -> Result<u64, BlsDorySharedLayoutError> {
    values.iter().try_fold(0u64, |sum, value| {
        sum.checked_add(*value)
            .ok_or(BlsDorySharedLayoutError::InvalidProofShape)
    })
}

fn projected_shared_scalar_fold_bytes(
    logical_scalars: u64,
    explicit_scalars: u64,
    generation: u32,
) -> Result<u64, BlsDorySharedLayoutError> {
    let divisor = 1u64
        .checked_shl(generation)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    projected_shared_scalar_artifact_bytes(
        logical_scalars
            .checked_shr(generation)
            .filter(|value| *value > 0)
            .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?,
        explicit_scalars.div_ceil(divisor),
        generation,
    )
}

fn add_projected_fold(
    current: &mut u64,
    peak: &mut u64,
    child: u64,
) -> Result<(), BlsDorySharedLayoutError> {
    let writing = current
        .checked_add(child)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    *peak = (*peak).max(writing);
    *current = writing;
    Ok(())
}

fn replace_projected_fold(
    current: &mut u64,
    peak: &mut u64,
    parent: u64,
    child: u64,
) -> Result<(), BlsDorySharedLayoutError> {
    let writing = current
        .checked_add(child)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    *peak = (*peak).max(writing);
    *current = writing
        .checked_sub(parent)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    Ok(())
}

/// One additional physical coefficient source appended after the shared
/// layout's canonical source order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BlsDoryAdditionalFoldSourceProjection {
    pub explicit_scalars: u64,
    /// The source remains a challenge-bound compact view through generation
    /// eight and materializes its first scalar artifact at generation nine.
    pub compress_first_eight_generations: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProjectedSharedFoldLifecycle {
    first_generation_fold_bytes: u64,
    second_generation_fold_bytes: u64,
    fifth_generation_fold_bytes: u64,
    eighth_generation_fold_bytes: u64,
    source_materialization_fold_bytes: u64,
    final_generation_fold_bytes: u64,
    aggregate_fold_peak_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BlsDoryComposedProductionScratchProjection {
    pub retained_source_bytes: u64,
    pub first_generation_fold_bytes: u64,
    pub second_generation_fold_bytes: u64,
    pub fifth_generation_fold_bytes: u64,
    pub eighth_generation_fold_bytes: u64,
    pub source_materialization_fold_bytes: u64,
    pub final_generation_fold_bytes: u64,
    pub aggregate_fold_peak_bytes: u64,
    pub aggregate_peak_bytes: u64,
}

#[allow(clippy::too_many_arguments)]
fn projected_shared_fold_lifecycle(
    padded_variables: usize,
    logical_scalars: u64,
    banks: u64,
    transition_count: u64,
    initialization_cells: u64,
    bank_cells: u64,
    weight_cells: u64,
    wiring_scalars: u64,
    additional_sources: &[BlsDoryAdditionalFoldSourceProjection],
) -> Result<ProjectedSharedFoldLifecycle, BlsDorySharedLayoutError> {
    if padded_variables <= BLS_DORY_SHARED_SOURCE_FOLD_GENERATIONS as usize
        || additional_sources
            .iter()
            .any(|source| source.explicit_scalars == 0 || source.explicit_scalars > logical_scalars)
    {
        return Err(BlsDorySharedLayoutError::InvalidProofShape);
    }
    let mut transition_cells = Vec::with_capacity(transition_count as usize);
    transition_cells.push(initialization_cells);
    transition_cells.extend(std::iter::repeat_n(bank_cells, banks as usize));
    let multiplicity_first_fold_bytes = projected_shared_scalar_fold_bytes(
        logical_scalars,
        BLS_DORY_RANGE_LOGUP_TABLE_VALUES as u64,
        1,
    )?
    .checked_mul(transition_count)
    .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let fixed_base_first_fold_bytes =
        projected_shared_scalar_fold_bytes(logical_scalars, initialization_cells, 1)?;
    let mut current_fold_bytes = multiplicity_first_fold_bytes
        .checked_add(fixed_base_first_fold_bytes)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let mut aggregate_fold_peak_bytes = current_fold_bytes;
    for source in additional_sources {
        if !source.compress_first_eight_generations {
            add_projected_fold(
                &mut current_fold_bytes,
                &mut aggregate_fold_peak_bytes,
                projected_shared_scalar_fold_bytes(logical_scalars, source.explicit_scalars, 1)?,
            )?;
        }
    }
    let first_generation_fold_bytes = current_fold_bytes;
    let mut second_generation_fold_bytes = 0;
    let mut fifth_generation_fold_bytes = 0;
    let mut eighth_generation_fold_bytes = 0;

    for generation in 2..=BLS_DORY_SHARED_SOURCE_FOLD_GENERATIONS {
        for _ in 0..transition_count {
            replace_projected_fold(
                &mut current_fold_bytes,
                &mut aggregate_fold_peak_bytes,
                projected_shared_scalar_fold_bytes(
                    logical_scalars,
                    BLS_DORY_RANGE_LOGUP_TABLE_VALUES as u64,
                    generation - 1,
                )?,
                projected_shared_scalar_fold_bytes(
                    logical_scalars,
                    BLS_DORY_RANGE_LOGUP_TABLE_VALUES as u64,
                    generation,
                )?,
            )?;
        }
        replace_projected_fold(
            &mut current_fold_bytes,
            &mut aggregate_fold_peak_bytes,
            projected_shared_scalar_fold_bytes(
                logical_scalars,
                initialization_cells,
                generation - 1,
            )?,
            projected_shared_scalar_fold_bytes(logical_scalars, initialization_cells, generation)?,
        )?;
        for source in additional_sources {
            if !source.compress_first_eight_generations {
                replace_projected_fold(
                    &mut current_fold_bytes,
                    &mut aggregate_fold_peak_bytes,
                    projected_shared_scalar_fold_bytes(
                        logical_scalars,
                        source.explicit_scalars,
                        generation - 1,
                    )?,
                    projected_shared_scalar_fold_bytes(
                        logical_scalars,
                        source.explicit_scalars,
                        generation,
                    )?,
                )?;
            }
        }
        match generation {
            2 => second_generation_fold_bytes = current_fold_bytes,
            5 => fifth_generation_fold_bytes = current_fold_bytes,
            BLS_DORY_SHARED_SOURCE_FOLD_GENERATIONS => {
                eighth_generation_fold_bytes = current_fold_bytes;
            }
            _ => {}
        }
    }

    let materialization_generation = BLS_DORY_SHARED_SOURCE_FOLD_GENERATIONS + 1;
    let mut ordinary_folds = Vec::new();
    for _ in 0..banks {
        for explicit in [bank_cells, weight_cells, bank_cells] {
            let child = projected_shared_scalar_fold_bytes(
                logical_scalars,
                explicit,
                materialization_generation,
            )?;
            add_projected_fold(
                &mut current_fold_bytes,
                &mut aggregate_fold_peak_bytes,
                child,
            )?;
            ordinary_folds.push((explicit, child));
        }
    }
    for cells in &transition_cells {
        let transition_explicit = cells
            .checked_mul(STRUCTURED_TRANSITION_ORACLES as u64)
            .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
        let transition_child = projected_shared_scalar_fold_bytes(
            logical_scalars,
            transition_explicit,
            materialization_generation,
        )?;
        add_projected_fold(
            &mut current_fold_bytes,
            &mut aggregate_fold_peak_bytes,
            transition_child,
        )?;
        ordinary_folds.push((transition_explicit, transition_child));

        let multiplicity_parent = projected_shared_scalar_fold_bytes(
            logical_scalars,
            BLS_DORY_RANGE_LOGUP_TABLE_VALUES as u64,
            BLS_DORY_SHARED_SOURCE_FOLD_GENERATIONS,
        )?;
        let multiplicity_child = projected_shared_scalar_fold_bytes(
            logical_scalars,
            BLS_DORY_RANGE_LOGUP_TABLE_VALUES as u64,
            materialization_generation,
        )?;
        replace_projected_fold(
            &mut current_fold_bytes,
            &mut aggregate_fold_peak_bytes,
            multiplicity_parent,
            multiplicity_child,
        )?;
        ordinary_folds.push((BLS_DORY_RANGE_LOGUP_TABLE_VALUES as u64, multiplicity_child));

        let mapped_child = transition_child;
        add_projected_fold(
            &mut current_fold_bytes,
            &mut aggregate_fold_peak_bytes,
            mapped_child,
        )?;
        ordinary_folds.push((transition_explicit, mapped_child));
    }
    let wiring_child = projected_shared_scalar_fold_bytes(
        logical_scalars,
        wiring_scalars,
        materialization_generation,
    )?;
    add_projected_fold(
        &mut current_fold_bytes,
        &mut aggregate_fold_peak_bytes,
        wiring_child,
    )?;
    ordinary_folds.push((wiring_scalars, wiring_child));
    let fixed_parent = projected_shared_scalar_fold_bytes(
        logical_scalars,
        initialization_cells,
        BLS_DORY_SHARED_SOURCE_FOLD_GENERATIONS,
    )?;
    let fixed_child = projected_shared_scalar_fold_bytes(
        logical_scalars,
        initialization_cells,
        materialization_generation,
    )?;
    replace_projected_fold(
        &mut current_fold_bytes,
        &mut aggregate_fold_peak_bytes,
        fixed_parent,
        fixed_child,
    )?;
    ordinary_folds.push((initialization_cells, fixed_child));

    for source in additional_sources {
        let child = projected_shared_scalar_fold_bytes(
            logical_scalars,
            source.explicit_scalars,
            materialization_generation,
        )?;
        if source.compress_first_eight_generations {
            add_projected_fold(
                &mut current_fold_bytes,
                &mut aggregate_fold_peak_bytes,
                child,
            )?;
        } else {
            replace_projected_fold(
                &mut current_fold_bytes,
                &mut aggregate_fold_peak_bytes,
                projected_shared_scalar_fold_bytes(
                    logical_scalars,
                    source.explicit_scalars,
                    BLS_DORY_SHARED_SOURCE_FOLD_GENERATIONS,
                )?,
                child,
            )?;
        }
        ordinary_folds.push((source.explicit_scalars, child));
    }
    let source_materialization_fold_bytes = current_fold_bytes;

    for generation in materialization_generation + 1..=padded_variables as u32 {
        for (explicit, parent) in &mut ordinary_folds {
            let child = projected_shared_scalar_fold_bytes(logical_scalars, *explicit, generation)?;
            replace_projected_fold(
                &mut current_fold_bytes,
                &mut aggregate_fold_peak_bytes,
                *parent,
                child,
            )?;
            *parent = child;
        }
    }

    Ok(ProjectedSharedFoldLifecycle {
        first_generation_fold_bytes,
        second_generation_fold_bytes,
        fifth_generation_fold_bytes,
        eighth_generation_fold_bytes,
        source_materialization_fold_bytes,
        final_generation_fold_bytes: current_fold_bytes,
        aggregate_fold_peak_bytes,
    })
}

fn projected_shared_scratch_bytes_for_shape(
    padded_variables: usize,
    banks: u64,
    batch: u64,
    dimension: u64,
    layers_per_bank: u64,
    max_abs_activation: u8,
    max_abs_weight: u8,
) -> Result<BlsDorySharedProductionScratchProjection, BlsDorySharedLayoutError> {
    let logical_scalars = 1u64
        .checked_shl(padded_variables as u32)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    if banks != MAX_BLS_DORY_SHARED_MATRIX_PROOFS as u64
        || banks + 1 != MAX_BLS_DORY_SHARED_TRANSITION_PROOFS as u64
    {
        return Err(BlsDorySharedLayoutError::InvalidProofShape);
    }
    let initialization_cells = batch
        .checked_mul(dimension)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let bank_cells = layers_per_bank
        .checked_mul(batch)
        .and_then(|value| value.checked_mul(dimension))
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let weight_cells = layers_per_bank
        .checked_mul(dimension)
        .and_then(|value| value.checked_mul(dimension))
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let wiring_scalars = bank_cells
        .checked_mul(
            banks
                .checked_mul(2)
                .and_then(|value| value.checked_add(1))
                .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?,
        )
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let transition_count = banks
        .checked_add(1)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let row_scalars = 1u64
        .checked_shl((padded_variables - padded_variables / 2) as u32)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;

    let matrix_source_per_bank = checked_projection_sum(&[
        projected_shared_signed_byte_source_bytes(
            logical_scalars,
            bank_cells,
            row_scalars,
            max_abs_activation,
        )?,
        projected_shared_signed_byte_source_bytes(
            logical_scalars,
            weight_cells,
            row_scalars,
            max_abs_weight,
        )?,
        projected_shared_signed_word_source_bytes(logical_scalars, bank_cells, bank_cells)?,
    ])?;
    let matrix_source_bytes = matrix_source_per_bank
        .checked_mul(banks)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let transition_source_bytes =
        projected_shared_transition_source_bytes(logical_scalars, initialization_cells)?
            .checked_add(
                projected_shared_transition_source_bytes(logical_scalars, bank_cells)?
                    .checked_mul(banks)
                    .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?,
            )
            .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let multiplicity_source_bytes = projected_shared_scalar_artifact_bytes(
        logical_scalars,
        BLS_DORY_RANGE_LOGUP_TABLE_VALUES as u64,
        1,
    )?
    .checked_mul(transition_count)
    .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let wiring_source_bytes = projected_shared_signed_byte_source_bytes(
        logical_scalars,
        wiring_scalars,
        row_scalars,
        max_abs_activation,
    )?;
    let fixed_base_source_bytes =
        projected_shared_scalar_artifact_bytes(logical_scalars, initialization_cells, 1)?;
    let retained_source_bytes = checked_projection_sum(&[
        matrix_source_bytes,
        transition_source_bytes,
        multiplicity_source_bytes,
        wiring_source_bytes,
        fixed_base_source_bytes,
    ])?;

    let matrix_first_fold_bytes = 0;
    let transition_first_fold_bytes = 0;
    let multiplicity_first_fold_bytes = projected_shared_scalar_fold_bytes(
        logical_scalars,
        BLS_DORY_RANGE_LOGUP_TABLE_VALUES as u64,
        1,
    )?
    .checked_mul(transition_count)
    .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let wiring_first_fold_bytes = 0;
    let fixed_base_first_fold_bytes =
        projected_shared_scalar_fold_bytes(logical_scalars, initialization_cells, 1)?;
    let lifecycle = projected_shared_fold_lifecycle(
        padded_variables,
        logical_scalars,
        banks,
        transition_count,
        initialization_cells,
        bank_cells,
        weight_cells,
        wiring_scalars,
        &[],
    )?;
    let first_generation_fold_bytes = lifecycle.first_generation_fold_bytes;
    let fifth_generation_fold_bytes = lifecycle.fifth_generation_fold_bytes;
    let source_materialization_fold_bytes = lifecycle.source_materialization_fold_bytes;
    let aggregate_fold_peak_bytes = lifecycle.aggregate_fold_peak_bytes;
    let aggregate_peak_bytes = retained_source_bytes
        .checked_add(aggregate_fold_peak_bytes)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;

    Ok(BlsDorySharedProductionScratchProjection {
        matrix_source_bytes,
        transition_source_bytes,
        multiplicity_source_bytes,
        wiring_source_bytes,
        fixed_base_source_bytes,
        retained_source_bytes,
        matrix_first_fold_bytes,
        transition_first_fold_bytes,
        multiplicity_first_fold_bytes,
        wiring_first_fold_bytes,
        fixed_base_first_fold_bytes,
        first_generation_fold_bytes,
        fifth_generation_fold_bytes,
        source_materialization_fold_bytes,
        aggregate_fold_peak_bytes,
        aggregate_peak_bytes,
    })
}

/// Project the exact current scratch peak for the three-bank production
/// topology. Unlike the earlier four-full-transition lower bound, this uses
/// one 2^19-cell initialization transition and three 2^26-cell bank
/// transitions, and includes matrix, multiplicity, wiring, and fixed-base
/// coefficient sources plus the complete aggregate-fold artifact lifecycle.
pub fn projected_shared_production_scratch_bytes()
-> Result<BlsDorySharedProductionScratchProjection, BlsDorySharedLayoutError> {
    projected_shared_scratch_bytes_for_shape(
        BLS_DORY_SHARED_PRODUCTION_VARIABLES,
        u64::from(PRODUCTION_V2_BANKS),
        u64::from(PRODUCTION_V2_BATCH),
        u64::from(PRODUCTION_V2_DIMENSION),
        u64::from(PRODUCTION_V2_LAYERS_PER_BANK),
        125,
        125,
    )
}

/// Extend the canonical production fold lifecycle with physical sources that
/// are appended after the shared layout's existing source order.
pub(crate) fn projected_shared_production_scratch_with_additional_sources(
    additional_retained_source_bytes: u64,
    additional_sources: &[BlsDoryAdditionalFoldSourceProjection],
) -> Result<BlsDoryComposedProductionScratchProjection, BlsDorySharedLayoutError> {
    let logical_scalars = 1u64
        .checked_shl(BLS_DORY_SHARED_PRODUCTION_VARIABLES as u32)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let banks = u64::from(PRODUCTION_V2_BANKS);
    let batch = u64::from(PRODUCTION_V2_BATCH);
    let dimension = u64::from(PRODUCTION_V2_DIMENSION);
    let layers_per_bank = u64::from(PRODUCTION_V2_LAYERS_PER_BANK);
    let transition_count = banks
        .checked_add(1)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let initialization_cells = batch
        .checked_mul(dimension)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let bank_cells = layers_per_bank
        .checked_mul(batch)
        .and_then(|value| value.checked_mul(dimension))
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let weight_cells = layers_per_bank
        .checked_mul(dimension)
        .and_then(|value| value.checked_mul(dimension))
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let wiring_scalars = bank_cells
        .checked_mul(
            banks
                .checked_mul(2)
                .and_then(|value| value.checked_add(1))
                .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?,
        )
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let lifecycle = projected_shared_fold_lifecycle(
        BLS_DORY_SHARED_PRODUCTION_VARIABLES,
        logical_scalars,
        banks,
        transition_count,
        initialization_cells,
        bank_cells,
        weight_cells,
        wiring_scalars,
        additional_sources,
    )?;
    let retained_source_bytes = projected_shared_production_scratch_bytes()?
        .retained_source_bytes
        .checked_add(additional_retained_source_bytes)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let aggregate_peak_bytes = retained_source_bytes
        .checked_add(lifecycle.aggregate_fold_peak_bytes)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;

    Ok(BlsDoryComposedProductionScratchProjection {
        retained_source_bytes,
        first_generation_fold_bytes: lifecycle.first_generation_fold_bytes,
        second_generation_fold_bytes: lifecycle.second_generation_fold_bytes,
        fifth_generation_fold_bytes: lifecycle.fifth_generation_fold_bytes,
        eighth_generation_fold_bytes: lifecycle.eighth_generation_fold_bytes,
        source_materialization_fold_bytes: lifecycle.source_materialization_fold_bytes,
        final_generation_fold_bytes: lifecycle.final_generation_fold_bytes,
        aggregate_fold_peak_bytes: lifecycle.aggregate_fold_peak_bytes,
        aggregate_peak_bytes,
    })
}

/// Project one Dory opening aggregate at the canonical production geometry.
pub fn projected_shared_production_opening_bytes() -> Result<usize, BlsDorySharedLayoutError> {
    Ok(projected_bls_dory_aggregate_bytes(
        BLS_DORY_SHARED_PRODUCTION_VARIABLES,
    )?)
}

/// Project the exact three-matrix/four-transition production frame after the
/// component-specific opening payloads have been replaced by one shared payload.
pub fn projected_shared_production_proof_bytes() -> Result<usize, BlsDorySharedLayoutError> {
    let matrix = projected_production_matrix_proof_bytes()?
        .checked_sub(projected_production_matrix_opening_bytes()?)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let arithmetic = projected_production_transition_proof_bytes()?
        .checked_sub(projected_production_transition_opening_bytes()?)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let range = projected_production_range_logup_proof_bytes()?
        .checked_sub(projected_production_range_logup_opening_bytes()?)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let wiring = projected_production_wiring_proof_bytes()?
        .checked_sub(projected_production_wiring_opening_bytes()?)
        .ok_or(BlsDorySharedLayoutError::InvalidProofShape)?;
    let mut total = SHARED_PROOF_HEADER_BYTES;
    for _ in 0..MAX_BLS_DORY_SHARED_MATRIX_PROOFS {
        total = framed_size(total, matrix)?;
    }
    for _ in 0..MAX_BLS_DORY_SHARED_TRANSITION_PROOFS {
        total = framed_size(total, arithmetic)?;
        total = framed_size(total, range)?;
    }
    total = framed_size(total, wiring)?;
    total = framed_size(
        total,
        shared_link_count(MAX_BLS_DORY_SHARED_MATRIX_PROOFS)?
            .checked_mul(BlsDoryFr::zero().compressed_size())
            .ok_or(BlsDorySharedLayoutError::ProofTooLarge)?,
    )?;
    total = framed_size(total, BlsDoryFr::zero().compressed_size())?;
    total = framed_size(total, projected_shared_production_opening_bytes()?)?;
    if total > MAX_BLS_DORY_SHARED_LAYOUT_PROOF_BYTES {
        return Err(BlsDorySharedLayoutError::ProofTooLarge);
    }
    Ok(total)
}

/// Fail closed until every shared-layout blocker is resolved.
pub fn require_bls_dory_shared_layout_production_ready() -> Result<(), BlsDorySharedLayoutError> {
    Err(BlsDorySharedLayoutError::NotProductionReady)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "whir-prototype")]
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::{fs::File, io};

    use serde_json::json;

    use super::*;
    use crate::{
        BuiltModelBankFixture, SmallModelBankFixture, StructuredMaskPolynomial,
        StructuredMatrixStatement, StructuredTransitionStatement, StructuredTransitionWitness,
        StructuredWiringStatement, V2_TRANSITION_MODULUS, build_small_model_bank,
        dory_bls12_381_aggregate::{
            MAX_BLS_DORY_AGGREGATE_CLAIMS, commit_bls_dory_padded_prefix_with_optional_scratch,
        },
        dory_bls12_381_execution_artifact::BlsDoryExecutionAccumulatorArtifactWriter,
        dory_bls12_381_matrix::{
            BlsDoryMatrixProof, prove_bls_dory_matrix_at_variables,
            verify_bls_dory_matrix_at_variables,
        },
        dory_bls12_381_prototype::{
            MAX_BLS_DORY_PROTOTYPE_VARIABLES, MAX_BLS_DORY_SETUP_VARIABLES,
            deterministic_bls_dory_setup,
        },
        dory_bls12_381_wiring::{
            BlsDoryWiringProof, prove_bls_dory_wiring_at_variables,
            verify_bls_dory_wiring_at_variables,
        },
        dory_v3_model::CanonicalBlsDoryGtHex,
        dory_v3_model_record::{
            DoryV3ModelCommitmentRecordV2,
            derive_bank_authenticated_dory_v3_model_commitment_record_v2,
        },
        dory_v3_suite::DORY_V3_MODEL_IDENTITY_VERSION,
        model_bank::{MODEL_BANK_HEADER_BYTES, ModelBankError},
    };
    #[cfg(feature = "whir-prototype")]
    use crate::{
        dory_bls12_381_blake3::prepare_native_blake3_test_opening_at_layout,
        dory_bls12_381_candidate::BlsDoryV3CandidatePayload,
        dory_bls12_381_output_bridge::BlsDoryOutputBridgeStatement,
    };

    const FIXTURE_VARIABLES: usize = 10;
    const OUTPUT_MODULUS: u64 = 251;
    const OUTPUT_CENTER: i64 = 125;
    static SCRATCH_NONCE: AtomicU64 = AtomicU64::new(1);

    struct FailAfterReader {
        inner: Cursor<Vec<u8>>,
        fail_after: u64,
    }

    impl FailAfterReader {
        fn new(bytes: Vec<u8>, fail_after: usize) -> Self {
            Self {
                inner: Cursor::new(bytes),
                fail_after: u64::try_from(fail_after).unwrap(),
            }
        }
    }

    impl Read for FailAfterReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let position = self.inner.position();
            if position >= self.fail_after {
                return Err(io::Error::other("injected model-bank read failure"));
            }
            let remaining = usize::try_from(self.fail_after - position).unwrap();
            let take = buffer.len().min(remaining);
            self.inner.read(&mut buffer[..take])
        }
    }

    struct ScratchDirectory(std::path::PathBuf);

    impl ScratchDirectory {
        fn create() -> Self {
            let nonce = SCRATCH_NONCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "cmfd-dory-shared-test-{}-{nonce}",
                std::process::id()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for ScratchDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn observed_directory_bytes(path: &Path) -> u64 {
        std::fs::read_dir(path)
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .filter_map(|entry| entry.metadata().ok())
            .map(|metadata| metadata.len())
            .sum()
    }

    #[cfg(feature = "whir-prototype")]
    struct ScratchPeakObserver {
        stop: std::sync::Arc<AtomicBool>,
        peak: std::sync::Arc<AtomicU64>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    #[cfg(feature = "whir-prototype")]
    impl ScratchPeakObserver {
        fn start(path: std::path::PathBuf) -> Self {
            let stop = std::sync::Arc::new(AtomicBool::new(false));
            let peak = std::sync::Arc::new(AtomicU64::new(0));
            let observer_stop = std::sync::Arc::clone(&stop);
            let observer_peak = std::sync::Arc::clone(&peak);
            let handle = std::thread::spawn(move || {
                while !observer_stop.load(Ordering::Relaxed) {
                    observer_peak.fetch_max(observed_directory_bytes(&path), Ordering::Relaxed);
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                observer_peak.fetch_max(observed_directory_bytes(&path), Ordering::Relaxed);
            });
            Self {
                stop,
                peak,
                handle: Some(handle),
            }
        }

        fn finish(mut self) -> u64 {
            self.stop.store(true, Ordering::Relaxed);
            self.handle.take().unwrap().join().unwrap();
            self.peak.load(Ordering::Relaxed)
        }
    }

    #[cfg(feature = "whir-prototype")]
    impl Drop for ScratchPeakObserver {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn authenticated_fixed_model_fixture() -> (
        BuiltModelBankFixture,
        ModelPcsIdentity,
        Vec<i64>,
        Vec<Vec<i64>>,
    ) {
        let base = [0, 125, 250, 126];
        let layers = [
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            [9, 10, 11, 12],
            [13, 14, 15, 16],
        ];
        let layer_slices = layers
            .iter()
            .map(|layer| layer.as_slice())
            .collect::<Vec<_>>();
        let suite = [0x51; 32];
        let provisional = build_small_model_bank(SmallModelBankFixture {
            model_version: 2,
            dimension: 2,
            batch: 2,
            base_input: &base,
            layers: &layer_slices,
            pcs_parameter_digest: suite,
            pcs_commitment_root: [0x52; 32],
        })
        .unwrap();
        let identity = ModelPcsIdentity {
            model_version: 2,
            batch: 2,
            dimension: 2,
            layers_per_bank: 2,
            model_byte_root: provisional.manifest.raw_blake3_root,
            pcs_suite_parameter_digest: suite,
            base_input_commitment: [0x61; 32],
            weight_bank_commitments: vec![[0x71; 32], [0x72; 32]],
        };
        let built = build_small_model_bank(SmallModelBankFixture {
            model_version: 2,
            dimension: 2,
            batch: 2,
            base_input: &base,
            layers: &layer_slices,
            pcs_parameter_digest: suite,
            pcs_commitment_root: identity.commitment_root().unwrap(),
        })
        .unwrap();
        let base_values = base
            .iter()
            .map(|value| i64::from(*value) - 125)
            .collect::<Vec<_>>();
        let weight_banks = layers
            .chunks_exact(2)
            .map(|bank| {
                bank.iter()
                    .flat_map(|layer| layer.iter())
                    .map(|value| i64::from(*value) - 125)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        (built, identity, base_values, weight_banks)
    }

    struct PreparedV5Fixture {
        built: BuiltModelBankFixture,
        identity: DoryV3ModelIdentityV1,
        setup: DeterministicBlsDorySetup,
        record_digest: Digest32,
        base_commitment: BlsDoryGt,
        weight_commitments: Vec<BlsDoryGt>,
    }

    fn prepared_v5_commit_bytes(bytes: &[u8], setup: &DeterministicBlsDorySetup) -> BlsDoryGt {
        const VARIABLES: usize = 4;
        let mut coefficients = bytes
            .iter()
            .map(|value| BlsDoryFr::from_i64(i64::from(*value) - 125))
            .collect::<Vec<_>>();
        coefficients.resize(1 << VARIABLES, BlsDoryFr::zero());
        commit_bls_dory_polynomial(
            coefficients,
            VARIABLES / 2,
            VARIABLES - VARIABLES / 2,
            setup,
        )
        .unwrap()
        .commitment()
    }

    fn prepared_v5_identity(
        manifest: &ModelBankManifest,
        setup: &DeterministicBlsDorySetup,
        base_commitment: BlsDoryGt,
        weight_commitments: &[BlsDoryGt],
    ) -> DoryV3ModelIdentityV1 {
        let suite_parameter_digest = [0x51; 32];
        let encode = |commitment| {
            CanonicalBlsDoryGtHex::from_commitment(commitment)
                .unwrap()
                .to_hex()
                .unwrap()
        };
        serde_json::from_value(json!({
            "identity_version": DORY_V3_MODEL_IDENTITY_VERSION,
            "model_version": 2,
            "batch": 2,
            "dimension": 2,
            "layers_per_bank": 2,
            "model_byte_root": manifest.raw_blake3_root,
            "layer_roots_aggregate": manifest.layer_roots_aggregate,
            "suite_parameter_digest": suite_parameter_digest,
            "setup_identity": setup.identity(),
            "padded_variables": 4,
            "base_input_commitment": encode(base_commitment),
            "weight_bank_commitments": weight_commitments
                .iter()
                .copied()
                .map(encode)
                .collect::<Vec<_>>(),
        }))
        .unwrap()
    }

    fn prepared_v5_fixture(wrong_role: Option<u32>) -> PreparedV5Fixture {
        let setup = deterministic_bls_dory_setup(4).unwrap();
        let base = [0, 125, 250, 126];
        let layers = [
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            [9, 10, 11, 12],
            [13, 14, 15, 16],
        ];
        let layer_slices = layers
            .iter()
            .map(|layer| layer.as_slice())
            .collect::<Vec<_>>();
        let base_commitment = prepared_v5_commit_bytes(&base, &setup);
        let weight_commitments = layers
            .chunks_exact(2)
            .map(|bank| {
                let bytes = bank
                    .iter()
                    .flat_map(|layer| layer.iter().copied())
                    .collect::<Vec<_>>();
                prepared_v5_commit_bytes(&bytes, &setup)
            })
            .collect::<Vec<_>>();
        let mut expected_base = base_commitment;
        let mut expected_weights = weight_commitments.clone();
        if let Some(role) = wrong_role {
            if role == 0 {
                let mut changed = base;
                changed[0] = 1;
                expected_base = prepared_v5_commit_bytes(&changed, &setup);
            } else {
                let bank = usize::try_from(role - 1).unwrap();
                let mut changed = layers[bank * 2..bank * 2 + 2]
                    .iter()
                    .flat_map(|layer| layer.iter().copied())
                    .collect::<Vec<_>>();
                changed[0] += 1;
                expected_weights[bank] = prepared_v5_commit_bytes(&changed, &setup);
            }
        }
        let provisional = build_small_model_bank(SmallModelBankFixture {
            model_version: 2,
            dimension: 2,
            batch: 2,
            base_input: &base,
            layers: &layer_slices,
            pcs_parameter_digest: [0x51; 32],
            pcs_commitment_root: [0x52; 32],
        })
        .unwrap();
        let identity = prepared_v5_identity(
            &provisional.manifest,
            &setup,
            expected_base,
            &expected_weights,
        );
        let built = build_small_model_bank(SmallModelBankFixture {
            model_version: 2,
            dimension: 2,
            batch: 2,
            base_input: &base,
            layers: &layer_slices,
            pcs_parameter_digest: identity.suite_parameter_digest(),
            pcs_commitment_root: identity.commitment_root().unwrap(),
        })
        .unwrap();
        identity.verify_manifest(&built.manifest).unwrap();
        PreparedV5Fixture {
            built,
            identity,
            setup,
            record_digest: Digest32::new([0x91; 32]),
            base_commitment,
            weight_commitments,
        }
    }

    fn prepare_v5_fixture_reader<R: Read>(
        fixture: &PreparedV5Fixture,
        reader: R,
        scratch_directory: &Path,
    ) -> Result<BlsDoryPreparedFixedModelV5, ModelBankFieldStreamError<BlsDoryFixedModelStreamError>>
    {
        let model_identity_digest = Digest32::new(fixture.identity.digest().unwrap());
        let sink = BlsDoryPreparedFixedModelV5Sink::new(
            &fixture.built.manifest,
            &fixture.identity,
            fixture.record_digest,
            model_identity_digest,
            &fixture.setup,
            scratch_directory,
        )
        .map_err(ModelBankFieldStreamError::Sink)?;
        verify_model_bank_into_staged_field_layout_sink(
            reader,
            &fixture.built.manifest,
            fixture.identity.layers_per_bank(),
            fixture.identity.weight_bank_count().unwrap(),
            sink,
        )
    }

    #[test]
    fn v5_prepared_model_publishes_only_exact_ordered_record_bound_polynomials() {
        let fixture = prepared_v5_fixture(None);
        let scratch = ScratchDirectory::create();
        let prepared =
            prepare_v5_fixture_reader(&fixture, Cursor::new(&fixture.built.bytes), &scratch.0)
                .unwrap();
        let identity_digest = Digest32::new(fixture.identity.digest().unwrap());
        assert_eq!(prepared.record_digest(), fixture.record_digest);
        assert_eq!(prepared.model_identity_digest(), identity_digest);
        assert_eq!(prepared.base_input.commitment(), fixture.base_commitment);
        assert_eq!(
            prepared
                .weight_banks
                .iter()
                .map(BlsDoryCommittedPolynomial::commitment)
                .collect::<Vec<_>>(),
            fixture.weight_commitments
        );
        assert!(prepared.is_bound_to_record_parts(
            fixture.record_digest,
            identity_digest,
            &fixture.identity
        ));
        assert!(!prepared.is_bound_to_record_parts(
            Digest32::new([0x92; 32]),
            identity_digest,
            &fixture.identity
        ));
        let other = prepared_v5_fixture(Some(0));
        assert!(!prepared.is_bound_to_record_parts(
            fixture.record_digest,
            Digest32::new(other.identity.digest().unwrap()),
            &other.identity
        ));
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 3);
        drop(prepared);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn v5_prepared_model_compares_every_ordered_commitment_and_cleans_failure_scratch() {
        for role in 0..=2 {
            let fixture = prepared_v5_fixture(Some(role));
            let scratch = ScratchDirectory::create();
            assert!(matches!(
                prepare_v5_fixture_reader(
                    &fixture,
                    Cursor::new(&fixture.built.bytes),
                    &scratch.0,
                ),
                Err(ModelBankFieldStreamError::Sink(
                    BlsDoryFixedModelStreamError::DoryV3CommitmentMismatch {
                        role: actual_role
                    }
                )) if actual_role == role
            ));
            assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
        }
    }

    #[test]
    fn v5_prepared_model_requires_authenticated_eof_and_cleans_failure_scratch() {
        let fixture = prepared_v5_fixture(None);
        let scratch = ScratchDirectory::create();
        let mut corrupted = fixture.built.bytes.clone();
        corrupted[MODEL_BANK_HEADER_BYTES] ^= 1;
        assert!(matches!(
            prepare_v5_fixture_reader(&fixture, Cursor::new(corrupted), &scratch.0),
            Err(ModelBankFieldStreamError::ModelBank(
                ModelBankError::RawRootMismatch
            ))
        ));
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);

        let mut trailing = fixture.built.bytes.clone();
        trailing.push(0);
        assert!(matches!(
            prepare_v5_fixture_reader(&fixture, Cursor::new(trailing), &scratch.0),
            Err(ModelBankFieldStreamError::ModelBank(
                ModelBankError::TrailingBytes
            ))
        ));
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn v5_prepared_model_cleans_scratch_after_midstream_read_failure_and_truncation() {
        let fixture = prepared_v5_fixture(None);
        let scratch = ScratchDirectory::create();
        let fail_after = MODEL_BANK_HEADER_BYTES
            + usize::try_from(fixture.built.manifest.base_input_bytes).unwrap()
            + usize::try_from(fixture.built.manifest.bytes_per_layer).unwrap()
            + 2;

        // The complete base and first layer have already reached the staged
        // sink when the second layer's read fails at this exact boundary.
        let failing = FailAfterReader::new(fixture.built.bytes.clone(), fail_after);
        assert!(matches!(
            prepare_v5_fixture_reader(&fixture, failing, &scratch.0),
            Err(ModelBankFieldStreamError::ModelBank(ModelBankError::Io(error)))
                if error.kind() == io::ErrorKind::Other
        ));
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);

        let truncated = fixture.built.bytes[..fail_after].to_vec();
        assert!(matches!(
            prepare_v5_fixture_reader(&fixture, Cursor::new(truncated), &scratch.0),
            Err(ModelBankFieldStreamError::ModelBank(
                ModelBankError::Truncated
            ))
        ));
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn layout_v5_prepared_model_rejects_wrong_record_and_reordered_commitments() {
        let fixture = prepared_v5_fixture(None);
        let scratch = ScratchDirectory::create();
        let prepared =
            prepare_v5_fixture_reader(&fixture, Cursor::new(&fixture.built.bytes), &scratch.0)
                .unwrap();
        let linked = linked_fixture(2);
        let matrix_statements = vec![linked.matrix_statement; linked.matrices.len()];
        let transition_statements = linked
            .transitions
            .iter()
            .map(|transition| transition.statement)
            .collect::<Vec<_>>();
        let layout = BlsDoryAggregateLayout::new(2, 2).unwrap();
        validate_layout_v5_prepared_model_commitments(
            &prepared,
            &fixture.identity,
            &matrix_statements,
            &transition_statements,
            layout,
            &fixture.setup,
        )
        .unwrap();
        assert!(!prepared.is_bound_to_record_parts(
            Digest32::new([0x92; 32]),
            Digest32::new(fixture.identity.digest().unwrap()),
            &fixture.identity,
        ));

        let mut reordered_weights = fixture.weight_commitments.clone();
        reordered_weights.swap(0, 1);
        let reordered_identity = prepared_v5_identity(
            &fixture.built.manifest,
            &fixture.setup,
            fixture.base_commitment,
            &reordered_weights,
        );
        assert_eq!(
            validate_layout_v5_prepared_model_commitments(
                &prepared,
                &reordered_identity,
                &matrix_statements,
                &transition_statements,
                layout,
                &fixture.setup,
            ),
            Err(BlsDorySharedLayoutError::FixedModelCommitment)
        );

        let substituted = prepared_v5_commit_bytes(&[2, 3, 4, 5, 6, 7, 8, 9], &fixture.setup);
        let mut substituted_weights = fixture.weight_commitments.clone();
        substituted_weights[0] = substituted;
        let substituted_identity = prepared_v5_identity(
            &fixture.built.manifest,
            &fixture.setup,
            fixture.base_commitment,
            &substituted_weights,
        );
        assert_eq!(
            validate_layout_v5_prepared_model_commitments(
                &prepared,
                &substituted_identity,
                &matrix_statements,
                &transition_statements,
                layout,
                &fixture.setup,
            ),
            Err(BlsDorySharedLayoutError::FixedModelCommitment)
        );
        drop(prepared);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn layout_v5_matrix_input_requires_no_parallel_weight_authority() {
        let fixture = linked_fixture(1);
        let input = BlsDorySharedLayoutV5MatrixProverInput {
            statement: fixture.matrix_statement,
            activations: &[],
            accumulators: &[],
        };
        assert_eq!(input.statement, fixture.matrix_statement);
        assert!(input.activations.is_empty());
        assert!(input.accumulators.is_empty());
    }

    #[test]
    fn v5_public_prepare_signature_requires_bank_authenticated_record_v2() {
        type PublicPrepare = fn(
            Cursor<Vec<u8>>,
            &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
            &DeterministicBlsDorySetup,
            &Path,
        ) -> Result<
            BlsDoryPreparedFixedModelV5,
            ModelBankFieldStreamError<BlsDoryFixedModelStreamError>,
        >;
        let entry: PublicPrepare =
            prepare_bls_dory_v3_fixed_model_from_bank_authenticated_record_with_scratch::<
                Cursor<Vec<u8>>,
            >;
        let _ = entry;
    }

    /// Unchanged-production gate for the canonical approximately 6-GiB bank.
    /// This intentionally performs the real bank-authentication pass before
    /// exercising the public preparation entry point; it has no fixture or
    /// serialized-record shortcut.
    #[test]
    #[ignore = "requires canonical 6-GiB model bank and pinned Record V2 ceremony artifacts"]
    fn v5_public_prepare_unchanged_production_six_gib_gate() {
        let bank_path = std::env::var("CMFD_DORY_V3_PRODUCTION_MODEL_BANK")
            .expect("set CMFD_DORY_V3_PRODUCTION_MODEL_BANK");
        let record_path = std::env::var("CMFD_DORY_V3_PRODUCTION_RECORD_V2")
            .expect("set CMFD_DORY_V3_PRODUCTION_RECORD_V2");
        let encoded_record = std::fs::read(record_path).unwrap();
        let pinned_record: DoryV3ModelCommitmentRecordV2 =
            serde_json::from_slice(&encoded_record).unwrap();
        let setup = deterministic_bls_dory_setup(BLS_DORY_SHARED_PRODUCTION_VARIABLES).unwrap();
        let structurally_validated = pinned_record
            .model_identity()
            .validate_production_structure(pinned_record.manifest(), &setup)
            .unwrap();
        let expected_file_bytes = u64::try_from(MODEL_BANK_HEADER_BYTES)
            .unwrap()
            .checked_add(pinned_record.manifest().payload_bytes)
            .unwrap();
        assert_eq!(
            std::fs::metadata(&bank_path).unwrap().len(),
            expected_file_bytes
        );

        let authenticated = derive_bank_authenticated_dory_v3_model_commitment_record_v2(
            File::open(&bank_path).unwrap(),
            &structurally_validated,
            &setup,
        )
        .unwrap();
        assert_eq!(authenticated.record(), &pinned_record);

        let scratch = ScratchDirectory::create();
        let prepared = prepare_bls_dory_v3_fixed_model_from_bank_authenticated_record_with_scratch(
            File::open(bank_path).unwrap(),
            &authenticated,
            &setup,
            &scratch.0,
        )
        .unwrap();
        assert!(prepared.is_bound_to_bank_authenticated_record(&authenticated));
        drop(prepared);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn authenticated_model_stream_matches_in_memory_fixed_commitments() {
        const PADDED_VARIABLES: usize = 5;
        let setup = deterministic_bls_dory_setup(6).unwrap();
        let (built, model, base, weight_banks) = authenticated_fixed_model_fixture();
        let weight_slices = weight_banks.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let expected = derive_bls_dory_fixed_model_identity(
            &model,
            &base,
            &weight_slices,
            PADDED_VARIABLES,
            &setup,
        )
        .unwrap();
        let streamed = derive_bls_dory_fixed_model_identity_from_verified_bank(
            Cursor::new(&built.bytes),
            &built.manifest,
            &model,
            PADDED_VARIABLES,
            &setup,
        )
        .unwrap();

        assert_eq!(streamed, expected);
        assert_eq!(streamed.digest().unwrap(), expected.digest().unwrap());
        assert_eq!(MAX_BLS_DORY_SETUP_VARIABLES, 33);
        assert_eq!(
            BLS_DORY_SHARED_PRODUCTION_VARIABLES,
            MAX_BLS_DORY_SETUP_VARIABLES
        );
    }

    #[test]
    fn verified_model_stream_publishes_reusable_exact_polynomials_and_cleans_up() {
        const PADDED_VARIABLES: usize = 4;
        let setup = deterministic_bls_dory_setup(6).unwrap();
        let (built, model, base, weight_banks) = authenticated_fixed_model_fixture();
        let weight_slices = weight_banks.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let expected = derive_bls_dory_fixed_model_identity(
            &model,
            &base,
            &weight_slices,
            PADDED_VARIABLES,
            &setup,
        )
        .unwrap();
        let scratch = ScratchDirectory::create();
        let prepared = prepare_bls_dory_fixed_model_from_verified_bank_with_scratch(
            Cursor::new(&built.bytes),
            &built.manifest,
            &model,
            PADDED_VARIABLES,
            &setup,
            &scratch.0,
        )
        .unwrap();
        assert_eq!(prepared.identity(), &expected);
        assert_eq!(
            prepared.base_input().commitment(),
            expected.base_input_commitment
        );
        assert_eq!(prepared.weight_banks().len(), weight_banks.len());
        assert_eq!(
            prepared
                .weight_banks()
                .iter()
                .map(BlsDoryCommittedPolynomial::commitment)
                .collect::<Vec<_>>(),
            expected.weight_bank_commitments
        );
        let statement = StructuredMatrixStatement {
            layers: 2,
            rows: 2,
            inner: 2,
            cols: 2,
            max_abs_activation: 10,
            max_abs_weight: 125,
            max_abs_accumulator: 2_000,
        };
        let activations = vec![1, 2, 3, 4, -1, 2, 5, -2];
        let weights = &weight_banks[0];
        let mut accumulators = Vec::with_capacity(8);
        for layer in 0..statement.layers {
            for row in 0..statement.rows {
                for column in 0..statement.cols {
                    let mut sum = 0i64;
                    for common in 0..statement.inner {
                        sum += activations
                            [(layer * statement.rows + row) * statement.inner + common]
                            * weights[(layer * statement.inner + common) * statement.cols + column];
                    }
                    accumulators.push(sum);
                }
            }
        }
        let ordinary = prove_bls_dory_matrix_deferred_at_variables_with_scratch(
            b"verified-model-matrix",
            statement,
            &activations,
            weights,
            &accumulators,
            PADDED_VARIABLES,
            &setup,
            &scratch.0,
        )
        .unwrap();
        let streamed = prove_bls_dory_matrix_deferred_with_precommitted_weight_and_scratch(
            b"verified-model-matrix",
            statement,
            &activations,
            &prepared.weight_banks()[0],
            &accumulators,
            PADDED_VARIABLES,
            &setup,
            &scratch.0,
        )
        .unwrap();
        assert_eq!(streamed.proof, ordinary.proof);
        assert_eq!(streamed.openings.claims(), ordinary.openings.claims());
        drop(streamed);
        drop(ordinary);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 3);
        drop(prepared);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn failed_verified_model_stream_publishes_no_polynomial_artifacts() {
        const PADDED_VARIABLES: usize = 5;
        let setup = deterministic_bls_dory_setup(6).unwrap();
        let (built, model, _, _) = authenticated_fixed_model_fixture();
        let scratch = ScratchDirectory::create();
        let mut corrupted = built.bytes.clone();
        corrupted[MODEL_BANK_HEADER_BYTES] ^= 1;
        assert!(matches!(
            prepare_bls_dory_fixed_model_from_verified_bank_with_scratch(
                Cursor::new(corrupted),
                &built.manifest,
                &model,
                PADDED_VARIABLES,
                &setup,
                &scratch.0,
            ),
            Err(ModelBankFieldStreamError::ModelBank(
                ModelBankError::RawRootMismatch
            ))
        ));
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);

        let mut trailing = built.bytes.clone();
        trailing.push(0);
        assert!(matches!(
            prepare_bls_dory_fixed_model_from_verified_bank_with_scratch(
                Cursor::new(trailing),
                &built.manifest,
                &model,
                PADDED_VARIABLES,
                &setup,
                &scratch.0,
            ),
            Err(ModelBankFieldStreamError::ModelBank(
                ModelBankError::TrailingBytes
            ))
        ));
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn authenticated_model_stream_never_publishes_failed_or_reordered_input() {
        const PADDED_VARIABLES: usize = 5;
        let setup = deterministic_bls_dory_setup(6).unwrap();
        let (built, model, _, _) = authenticated_fixed_model_fixture();

        let mut corrupted = built.bytes.clone();
        corrupted[MODEL_BANK_HEADER_BYTES] ^= 1;
        assert!(matches!(
            derive_bls_dory_fixed_model_identity_from_verified_bank(
                Cursor::new(corrupted),
                &built.manifest,
                &model,
                PADDED_VARIABLES,
                &setup,
            ),
            Err(ModelBankFieldStreamError::ModelBank(
                ModelBankError::RawRootMismatch
            ))
        ));

        let mut trailing = built.bytes.clone();
        trailing.push(0);
        assert!(matches!(
            derive_bls_dory_fixed_model_identity_from_verified_bank(
                Cursor::new(trailing),
                &built.manifest,
                &model,
                PADDED_VARIABLES,
                &setup,
            ),
            Err(ModelBankFieldStreamError::ModelBank(
                ModelBankError::TrailingBytes
            ))
        ));

        let mut sink = BlsDoryFixedModelSink::new(&model, PADDED_VARIABLES, &setup).unwrap();
        assert_eq!(
            sink.write_chunk(ModelFieldChunk {
                role: ModelPcsRole::WeightBank { index: 0 },
                role_offset: 0,
                role_elements: 8,
                elements: &[GOLDILOCKS_MODULUS - 124],
            }),
            Err(BlsDoryFixedModelStreamError::InvalidChunk)
        );
        assert_eq!(
            bls_scalar_from_model_field(126),
            Err(BlsDoryFixedModelStreamError::InvalidFieldValue)
        );
        assert_eq!(
            bls_scalar_from_model_field(GOLDILOCKS_MODULUS),
            Err(BlsDoryFixedModelStreamError::InvalidFieldValue)
        );
    }

    fn matrix_fixture() -> (StructuredMatrixStatement, Vec<i64>, Vec<i64>, Vec<i64>) {
        let statement = StructuredMatrixStatement {
            layers: 2,
            rows: 2,
            inner: 2,
            cols: 2,
            max_abs_activation: 10,
            max_abs_weight: 10,
            max_abs_accumulator: 100,
        };
        (
            statement,
            vec![1, 2, 3, 4, -1, 2, 5, -2],
            vec![2, 1, -1, 3, 4, -2, 1, 5],
            vec![0, 7, 2, 15, -2, 12, 18, -20],
        )
    }

    fn transition_fixture() -> (
        StructuredTransitionStatement,
        StructuredMaskPolynomial,
        StructuredTransitionWitness,
    ) {
        let statement = StructuredTransitionStatement {
            layers: 2,
            rows: 2,
            cols: 2,
            max_abs_accumulator: 65_536,
            max_mask: 5_000,
        };
        let mask = StructuredMaskPolynomial::from_challenge(&[0x5a; 32], 2, 2, 2).unwrap();
        let mut witness = StructuredTransitionWitness {
            accumulators: Vec::new(),
            masks: Vec::new(),
            encoded: Vec::new(),
            square_quotients: Vec::new(),
            square_remainders: Vec::new(),
            cube_quotients: Vec::new(),
            cube_remainders: Vec::new(),
            output_quotients: Vec::new(),
            output_remainders: Vec::new(),
            negative: Vec::new(),
            activations: Vec::new(),
        };
        let modulus = u64::from(V2_TRANSITION_MODULUS);
        for index in 0..statement.layers * statement.rows * statement.cols {
            let accumulator = index as i64 * 113 - 390;
            let mask_value = mask.value_at_boolean_index(statement, index).unwrap();
            let combined = i128::from(accumulator) + i128::from(mask_value);
            let negative = u64::from(combined < 0);
            let encoded = u64::try_from(if combined < 0 {
                i128::from(modulus) + combined
            } else {
                combined
            })
            .unwrap();
            let square = encoded * encoded;
            let square_quotient = square / modulus;
            let square_remainder = square % modulus;
            let cube = square_remainder * encoded;
            let cube_quotient = cube / modulus;
            let cube_remainder = cube % modulus;
            let output_quotient = cube_remainder / OUTPUT_MODULUS;
            let output_remainder = cube_remainder % OUTPUT_MODULUS;

            witness.accumulators.push(accumulator);
            witness.masks.push(mask_value);
            witness.encoded.push(encoded);
            witness.square_quotients.push(square_quotient);
            witness.square_remainders.push(square_remainder);
            witness.cube_quotients.push(cube_quotient);
            witness.cube_remainders.push(cube_remainder);
            witness.output_quotients.push(output_quotient);
            witness.output_remainders.push(output_remainder);
            witness.negative.push(negative);
            witness
                .activations
                .push(i64::try_from(output_remainder).unwrap() - OUTPUT_CENTER);
        }
        (statement, mask, witness)
    }

    #[test]
    fn scratch_transition_and_logup_share_one_oracle_artifact() {
        let setup = deterministic_bls_dory_setup(FIXTURE_VARIABLES).unwrap();
        let (statement, mask, witness) = transition_fixture();
        let scratch = ScratchDirectory::create();
        let arithmetic = prove_bls_dory_transition_deferred_at_variables_with_scratch(
            b"shared-transition-artifact",
            statement,
            &mask,
            &witness,
            FIXTURE_VARIABLES,
            &setup,
            &scratch.0,
        )
        .unwrap();
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 1);
        let transition = arithmetic.openings.polynomial(0).unwrap();
        let range = prove_bls_dory_range_logup_deferred_with_precommitted_transition_and_scratch(
            b"shared-transition-artifact",
            statement,
            &witness,
            transition,
            FIXTURE_VARIABLES,
            &setup,
            &scratch.0,
        )
        .unwrap();
        assert_eq!(
            arithmetic.proof.oracle_commitment,
            range.proof.transition_commitment
        );
        assert!(transition.shares_coefficient_source(range.openings.polynomial(0).unwrap()));
        assert_eq!(
            transition.coefficient_artifact_path(),
            range
                .openings
                .polynomial(2)
                .unwrap()
                .coefficient_artifact_path()
        );
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 2);

        let wrong_coefficients =
            vec![BlsDoryFr::zero(); statement.elements().unwrap() * STRUCTURED_TRANSITION_ORACLES];
        let wrong_transition = commit_bls_dory_padded_prefix_with_optional_scratch(
            &wrong_coefficients,
            FIXTURE_VARIABLES / 2,
            FIXTURE_VARIABLES - FIXTURE_VARIABLES / 2,
            &setup,
            Some(&scratch.0),
        )
        .unwrap();
        assert!(matches!(
            prove_bls_dory_range_logup_deferred_with_precommitted_transition_and_scratch(
                b"shared-transition-artifact",
                statement,
                &witness,
                &wrong_transition,
                FIXTURE_VARIABLES,
                &setup,
                &scratch.0,
            ),
            Err(BlsDoryRangeLogUpError::Aggregate(
                BlsDoryAggregateError::CoefficientSource
            ))
        ));
        drop(wrong_transition);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 2);
        drop(range);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 1);
        drop(arithmetic);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    fn wiring_fixture() -> (StructuredWiringStatement, Vec<i64>, Vec<i64>, Vec<i64>) {
        (
            StructuredWiringStatement {
                banks: 2,
                layers_per_bank: 2,
                rows: 2,
                cols: 2,
                max_abs_activation: 100,
            },
            vec![1, 2, 3, 4],
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            vec![5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
        )
    }

    struct LinkedMatrixWitness {
        activations: Vec<i64>,
        weights: Vec<i64>,
        accumulators: Vec<i64>,
    }

    struct LinkedTransitionWitness {
        statement: StructuredTransitionStatement,
        mask: StructuredMaskPolynomial,
        witness: StructuredTransitionWitness,
    }

    struct LinkedFixture {
        matrix_statement: StructuredMatrixStatement,
        matrices: Vec<LinkedMatrixWitness>,
        transitions: Vec<LinkedTransitionWitness>,
        wiring_statement: StructuredWiringStatement,
        initial: Vec<i64>,
        inputs: Vec<i64>,
        outputs: Vec<i64>,
    }

    fn linked_fixture(banks: usize) -> LinkedFixture {
        linked_fixture_shape(banks, 2, 2, 2)
    }

    fn linked_fixture_shape(
        banks: usize,
        layers: usize,
        rows: usize,
        cols: usize,
    ) -> LinkedFixture {
        let initialization_statement = StructuredTransitionStatement {
            layers: 1,
            rows,
            cols,
            max_abs_accumulator: 65_536,
            max_mask: 5_000,
        };
        let initialization_mask =
            StructuredMaskPolynomial::from_challenge(&[0x31; 32], 1, rows, cols).unwrap();
        let initialization_accumulators = (0..rows * cols)
            .map(|index| [-7, 11, 23, -19][index % 4])
            .collect::<Vec<_>>();
        let initialization_witness = transition_witness_from_accumulators(
            initialization_statement,
            &initialization_mask,
            &initialization_accumulators,
        );
        let initial = initialization_witness.activations.clone();
        let mut transitions = vec![LinkedTransitionWitness {
            statement: initialization_statement,
            mask: initialization_mask,
            witness: initialization_witness,
        }];
        let matrix_statement = StructuredMatrixStatement {
            layers,
            rows,
            inner: cols,
            cols,
            max_abs_activation: 125,
            max_abs_weight: 10,
            max_abs_accumulator: 65_536,
        };
        let transition_statement = StructuredTransitionStatement {
            layers,
            rows,
            cols,
            max_abs_accumulator: 65_536,
            max_mask: 5_000,
        };
        let mut matrices = Vec::with_capacity(banks);
        let mut wiring_inputs = Vec::new();
        let mut wiring_outputs = Vec::new();
        let mut current = initial.clone();
        for bank in 0..banks {
            let mask = StructuredMaskPolynomial::from_challenge(
                &[0x40 + bank as u8; 32],
                layers,
                rows,
                cols,
            )
            .unwrap();
            let weights = (0..layers * cols * cols)
                .map(|index| ((index + bank) % 5) as i64 - 2)
                .collect::<Vec<_>>();
            let mut activations = Vec::with_capacity(layers * rows * cols);
            let mut accumulators = Vec::with_capacity(layers * rows * cols);
            let mut outputs = Vec::with_capacity(layers * rows * cols);
            for layer in 0..layers {
                activations.extend_from_slice(&current);
                let mut layer_accumulators = Vec::with_capacity(rows * cols);
                for row in 0..rows {
                    for col in 0..cols {
                        let mut accumulator = 0_i64;
                        for common in 0..cols {
                            accumulator += current[row * cols + common]
                                * weights[(layer * cols + common) * cols + col];
                        }
                        layer_accumulators.push(accumulator);
                    }
                }
                let layer_offset = layer * rows * cols;
                let layer_witness = transition_witness_from_accumulators_at_offset(
                    transition_statement,
                    &mask,
                    &layer_accumulators,
                    layer_offset,
                );
                accumulators.extend_from_slice(&layer_accumulators);
                outputs.extend_from_slice(&layer_witness.activations);
                current = layer_witness.activations;
            }
            let witness =
                transition_witness_from_accumulators(transition_statement, &mask, &accumulators);
            assert_eq!(witness.activations, outputs);
            wiring_inputs.extend_from_slice(&activations);
            wiring_outputs.extend_from_slice(&outputs);
            matrices.push(LinkedMatrixWitness {
                activations,
                weights,
                accumulators,
            });
            transitions.push(LinkedTransitionWitness {
                statement: transition_statement,
                mask,
                witness,
            });
        }
        LinkedFixture {
            matrix_statement,
            matrices,
            transitions,
            wiring_statement: StructuredWiringStatement {
                banks,
                layers_per_bank: layers,
                rows,
                cols,
                max_abs_activation: 125,
            },
            initial,
            inputs: wiring_inputs,
            outputs: wiring_outputs,
        }
    }

    fn fixed_model_fixture(
        fixture: &LinkedFixture,
        setup: &DeterministicBlsDorySetup,
    ) -> (ModelPcsIdentity, BlsDoryFixedModelIdentity) {
        fixed_model_fixture_at_variables(fixture, setup, FIXTURE_VARIABLES)
    }

    fn fixed_model_fixture_at_variables(
        fixture: &LinkedFixture,
        setup: &DeterministicBlsDorySetup,
        padded_variables: usize,
    ) -> (ModelPcsIdentity, BlsDoryFixedModelIdentity) {
        let model = ModelPcsIdentity {
            model_version: 1,
            batch: fixture.wiring_statement.rows as u32,
            dimension: fixture.wiring_statement.cols as u32,
            layers_per_bank: fixture.wiring_statement.layers_per_bank as u32,
            model_byte_root: [0x11; 32],
            pcs_suite_parameter_digest: [0x22; 32],
            base_input_commitment: [0x33; 32],
            weight_bank_commitments: (0..fixture.matrices.len())
                .map(|bank| [0x40 + bank as u8; 32])
                .collect(),
        };
        let weights = fixture
            .matrices
            .iter()
            .map(|matrix| matrix.weights.as_slice())
            .collect::<Vec<_>>();
        let fixed = if padded_variables <= MAX_BLS_DORY_PROTOTYPE_VARIABLES {
            derive_bls_dory_fixed_model_identity(
                &model,
                &fixture.transitions[0].witness.accumulators,
                &weights,
                padded_variables,
                setup,
            )
            .unwrap()
        } else {
            let scratch = ScratchDirectory::create();
            let base = commit_fixed_table_with_optional_scratch(
                &fixture.transitions[0].witness.accumulators,
                padded_variables,
                setup,
                Some(&scratch.0),
            )
            .unwrap();
            let committed_weights = weights
                .iter()
                .map(|weight| {
                    commit_fixed_table_with_optional_scratch(
                        weight,
                        padded_variables,
                        setup,
                        Some(&scratch.0),
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();
            let identity = BlsDoryFixedModelIdentity {
                protocol_version: BLS_DORY_FIXED_MODEL_IDENTITY_VERSION,
                model_pcs_identity_digest: model.digest().unwrap(),
                setup_identity: setup.identity(),
                base_input_commitment: base.commitment(),
                weight_bank_commitments: committed_weights
                    .iter()
                    .map(BlsDoryCommittedPolynomial::commitment)
                    .collect(),
            };
            identity
                .validate(&model, fixture.matrices.len(), setup)
                .unwrap();
            drop(committed_weights);
            drop(base);
            assert_eq!(observed_directory_bytes(&scratch.0), 0);
            identity
        };
        (model, fixed)
    }

    fn execution_artifact_linked_fixture(challenge: [u8; 32]) -> LinkedFixture {
        const BANKS: usize = 1;
        const LAYERS: usize = 2;
        const ROWS: usize = 4;
        const COLS: usize = 4;

        let initialization_statement = StructuredTransitionStatement {
            layers: 1,
            rows: ROWS,
            cols: COLS,
            max_abs_accumulator: 65_536,
            max_mask: 5_000,
        };
        let transition_statement = StructuredTransitionStatement {
            layers: LAYERS,
            ..initialization_statement
        };
        let initialization_mask =
            StructuredMaskPolynomial::from_virtual_challenge(&challenge, ROWS, COLS).unwrap();
        let initialization_accumulators = (0..ROWS * COLS)
            .map(|index| (index as i64 * 17) % 47 - 23)
            .collect::<Vec<_>>();
        let initialization_witness = transition_witness_from_accumulators(
            initialization_statement,
            &initialization_mask,
            &initialization_accumulators,
        );
        let initial = initialization_witness.activations.clone();
        let mut current = initial.clone();
        let mut matrices = Vec::with_capacity(BANKS);
        let mut transitions = vec![LinkedTransitionWitness {
            statement: initialization_statement,
            mask: initialization_mask,
            witness: initialization_witness,
        }];
        let mut wiring_inputs = Vec::new();
        let mut wiring_outputs = Vec::new();
        for bank in 0..BANKS {
            let first_layer = u32::try_from(bank * LAYERS).unwrap();
            let mask = StructuredMaskPolynomial::from_challenge_at_layer_offset(
                &challenge,
                first_layer,
                LAYERS,
                ROWS,
                COLS,
            )
            .unwrap();
            let weights = (0..LAYERS * COLS * COLS)
                .map(|index| ((index + bank) % 5) as i64 - 2)
                .collect::<Vec<_>>();
            let mut activations = Vec::with_capacity(LAYERS * ROWS * COLS);
            let mut accumulators = Vec::with_capacity(LAYERS * ROWS * COLS);
            let mut outputs = Vec::with_capacity(LAYERS * ROWS * COLS);
            for layer in 0..LAYERS {
                activations.extend_from_slice(&current);
                let mut layer_accumulators = Vec::with_capacity(ROWS * COLS);
                for row in 0..ROWS {
                    for col in 0..COLS {
                        let mut accumulator = 0_i64;
                        for common in 0..COLS {
                            accumulator += current[row * COLS + common]
                                * weights[(layer * COLS + common) * COLS + col];
                        }
                        layer_accumulators.push(accumulator);
                    }
                }
                let layer_witness = transition_witness_from_accumulators_at_offset(
                    transition_statement,
                    &mask,
                    &layer_accumulators,
                    layer * ROWS * COLS,
                );
                accumulators.extend_from_slice(&layer_accumulators);
                outputs.extend_from_slice(&layer_witness.activations);
                current = layer_witness.activations;
            }
            let witness =
                transition_witness_from_accumulators(transition_statement, &mask, &accumulators);
            assert_eq!(witness.activations, outputs);
            wiring_inputs.extend_from_slice(&activations);
            wiring_outputs.extend_from_slice(&outputs);
            matrices.push(LinkedMatrixWitness {
                activations,
                weights,
                accumulators,
            });
            transitions.push(LinkedTransitionWitness {
                statement: transition_statement,
                mask,
                witness,
            });
        }
        LinkedFixture {
            matrix_statement: StructuredMatrixStatement {
                layers: LAYERS,
                rows: ROWS,
                inner: COLS,
                cols: COLS,
                max_abs_activation: 125,
                max_abs_weight: 10,
                max_abs_accumulator: 65_536,
            },
            matrices,
            transitions,
            wiring_statement: StructuredWiringStatement {
                banks: BANKS,
                layers_per_bank: LAYERS,
                rows: ROWS,
                cols: COLS,
                max_abs_activation: 125,
            },
            initial,
            inputs: wiring_inputs,
            outputs: wiring_outputs,
        }
    }

    fn prepared_fixed_model_fixture(
        fixture: &LinkedFixture,
        setup: &DeterministicBlsDorySetup,
        padded_variables: usize,
        scratch_directory: &Path,
    ) -> (ModelPcsIdentity, BlsDoryPreparedFixedModel) {
        let model = ModelPcsIdentity {
            model_version: 1,
            batch: fixture.wiring_statement.rows as u32,
            dimension: fixture.wiring_statement.cols as u32,
            layers_per_bank: fixture.wiring_statement.layers_per_bank as u32,
            model_byte_root: [0x11; 32],
            pcs_suite_parameter_digest: [0x22; 32],
            base_input_commitment: [0x33; 32],
            weight_bank_commitments: (0..fixture.matrices.len())
                .map(|bank| [0x40 + bank as u8; 32])
                .collect(),
        };
        let base_input = commit_fixed_table_with_optional_scratch(
            &fixture.transitions[0].witness.accumulators,
            padded_variables,
            setup,
            Some(scratch_directory),
        )
        .unwrap();
        let weight_banks = fixture
            .matrices
            .iter()
            .map(|matrix| {
                commit_fixed_table_with_optional_scratch(
                    &matrix.weights,
                    padded_variables,
                    setup,
                    Some(scratch_directory),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let identity = BlsDoryFixedModelIdentity {
            protocol_version: BLS_DORY_FIXED_MODEL_IDENTITY_VERSION,
            model_pcs_identity_digest: model.digest().unwrap(),
            setup_identity: setup.identity(),
            base_input_commitment: base_input.commitment(),
            weight_bank_commitments: weight_banks
                .iter()
                .map(BlsDoryCommittedPolynomial::commitment)
                .collect(),
        };
        identity
            .validate(&model, fixture.matrices.len(), setup)
            .unwrap();
        (
            model,
            BlsDoryPreparedFixedModel {
                identity,
                base_input,
                weight_banks,
            },
        )
    }

    fn execution_artifact_for_linked_fixture(
        fixture: &LinkedFixture,
        context: BlsDoryExecutionAccumulatorArtifactContext,
        directory: &Path,
    ) -> BlsDoryExecutionAccumulatorArtifact {
        let mut writer =
            BlsDoryExecutionAccumulatorArtifactWriter::create_new(directory, context).unwrap();
        let chunk_cells = context.authentication_chunk_cells();
        for chunk in fixture.transitions[0]
            .witness
            .accumulators
            .chunks(chunk_cells)
        {
            let chunk = chunk
                .iter()
                .copied()
                .map(i32::try_from)
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            writer
                .write_column_chunk(BlsDoryExecutionAccumulatorColumn::Initialization, &chunk)
                .unwrap();
        }
        let cells = context.cells_per_column();
        for (bank, matrix) in fixture.matrices.iter().enumerate() {
            for layer in 0..context.layers_per_bank() {
                let column = BlsDoryExecutionAccumulatorColumn::BankLayer { bank, layer };
                for chunk in
                    matrix.accumulators[layer * cells..(layer + 1) * cells].chunks(chunk_cells)
                {
                    let chunk = chunk
                        .iter()
                        .copied()
                        .map(i32::try_from)
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap();
                    writer.write_column_chunk(column, &chunk).unwrap();
                }
            }
        }
        writer.finish().unwrap()
    }

    fn transition_witness_from_accumulators(
        statement: StructuredTransitionStatement,
        mask: &StructuredMaskPolynomial,
        accumulators: &[i64],
    ) -> StructuredTransitionWitness {
        transition_witness_from_accumulators_at_offset(statement, mask, accumulators, 0)
    }

    fn transition_witness_from_accumulators_at_offset(
        statement: StructuredTransitionStatement,
        mask: &StructuredMaskPolynomial,
        accumulators: &[i64],
        offset: usize,
    ) -> StructuredTransitionWitness {
        let mut witness = StructuredTransitionWitness {
            accumulators: Vec::new(),
            masks: Vec::new(),
            encoded: Vec::new(),
            square_quotients: Vec::new(),
            square_remainders: Vec::new(),
            cube_quotients: Vec::new(),
            cube_remainders: Vec::new(),
            output_quotients: Vec::new(),
            output_remainders: Vec::new(),
            negative: Vec::new(),
            activations: Vec::new(),
        };
        let modulus = u64::from(V2_TRANSITION_MODULUS);
        for (local_index, accumulator) in accumulators.iter().copied().enumerate() {
            let index = offset + local_index;
            let mask_value = mask.value_at_boolean_index(statement, index).unwrap();
            let combined = i128::from(accumulator) + i128::from(mask_value);
            let negative = u64::from(combined < 0);
            let encoded = u64::try_from(if combined < 0 {
                i128::from(modulus) + combined
            } else {
                combined
            })
            .unwrap();
            let square = encoded * encoded;
            let square_quotient = square / modulus;
            let square_remainder = square % modulus;
            let cube = square_remainder * encoded;
            let cube_quotient = cube / modulus;
            let cube_remainder = cube % modulus;
            let output_quotient = cube_remainder / OUTPUT_MODULUS;
            let output_remainder = cube_remainder % OUTPUT_MODULUS;
            witness.accumulators.push(accumulator);
            witness.masks.push(mask_value);
            witness.encoded.push(encoded);
            witness.square_quotients.push(square_quotient);
            witness.square_remainders.push(square_remainder);
            witness.cube_quotients.push(cube_quotient);
            witness.cube_remainders.push(cube_remainder);
            witness.output_quotients.push(output_quotient);
            witness.output_remainders.push(output_remainder);
            witness.negative.push(negative);
            witness
                .activations
                .push(i64::try_from(output_remainder).unwrap() - OUTPUT_CENTER);
        }
        witness
    }

    #[test]
    fn all_scalar_components_accept_one_exact_shared_layout() {
        let setup = deterministic_bls_dory_setup(FIXTURE_VARIABLES).unwrap();
        let (matrix_statement, activations, weights, accumulators) = matrix_fixture();
        let matrix = prove_bls_dory_matrix_at_variables(
            b"shared-layout",
            matrix_statement,
            &activations,
            &weights,
            &accumulators,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();
        verify_bls_dory_matrix_at_variables(
            b"shared-layout",
            matrix_statement,
            &matrix,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();

        let (transition_statement, mask, witness) = transition_fixture();
        let transition = prove_bls_dory_transition_range_at_variables(
            b"shared-layout",
            transition_statement,
            &mask,
            &witness,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();
        verify_bls_dory_transition_range_at_variables(
            b"shared-layout",
            transition_statement,
            &mask,
            &transition,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();

        let (wiring_statement, initial, inputs, outputs) = wiring_fixture();
        let wiring = prove_bls_dory_wiring_at_variables(
            b"shared-layout",
            wiring_statement,
            &initial,
            &inputs,
            &outputs,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();
        verify_bls_dory_wiring_at_variables(
            b"shared-layout",
            wiring_statement,
            &wiring,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();

        assert_eq!(usize::from(matrix.padded_variables), FIXTURE_VARIABLES);
        assert_eq!(
            usize::from(transition.arithmetic.packed_variables),
            FIXTURE_VARIABLES
        );
        assert_eq!(
            usize::from(transition.range.packed_variables),
            FIXTURE_VARIABLES
        );
        assert_eq!(usize::from(wiring.packed_variables), FIXTURE_VARIABLES);
        assert_eq!(matrix.opening_proof.len(), 21_775);
        assert_eq!(transition.arithmetic.opening_proof.len(), 21_775);
        assert_eq!(transition.range.opening_proof.len(), 21_775);
        assert_eq!(wiring.opening_proof.len(), 21_775);
        let fixture_claims =
            3 + BLS_DORY_TRANSITION_OPENING_CLAIMS + BLS_DORY_RANGE_LOGUP_OPENING_CLAIMS + 9;
        assert_eq!(fixture_claims, 28);
        assert!(fixture_claims <= MAX_BLS_DORY_AGGREGATE_CLAIMS);

        let matrix_encoded = matrix.encode(matrix_statement).unwrap();
        assert_eq!(
            BlsDoryMatrixProof::decode_with_variables(
                &matrix_encoded,
                matrix_statement,
                FIXTURE_VARIABLES,
            )
            .unwrap(),
            matrix
        );
        let transition_encoded = transition.arithmetic.encode(transition_statement).unwrap();
        assert_eq!(
            BlsDoryTransitionProof::decode_with_variables(
                &transition_encoded,
                transition_statement,
                FIXTURE_VARIABLES,
            )
            .unwrap(),
            transition.arithmetic
        );
        let wiring_encoded = wiring.encode(wiring_statement).unwrap();
        assert_eq!(
            BlsDoryWiringProof::decode_with_variables(
                &wiring_encoded,
                wiring_statement,
                FIXTURE_VARIABLES,
            )
            .unwrap(),
            wiring
        );
    }

    #[test]
    fn execution_artifact_shared_layout_matches_complete_materialized_proof_and_lifecycle() {
        const ARTIFACT_VARIABLES: usize = 12;
        let setup = deterministic_bls_dory_setup(ARTIFACT_VARIABLES).unwrap();
        let challenge = [0x5a; 32];
        let fixture = execution_artifact_linked_fixture(challenge);
        let matrix_statements = vec![fixture.matrix_statement; fixture.matrices.len()];
        let transition_statements = fixture
            .transitions
            .iter()
            .map(|transition| transition.statement)
            .collect::<Vec<_>>();
        let masks = fixture
            .transitions
            .iter()
            .map(|transition| &transition.mask)
            .collect::<Vec<_>>();
        let transition_inputs = fixture
            .transitions
            .iter()
            .map(|transition| BlsDoryTransitionProverInput {
                statement: transition.statement,
                mask_polynomial: &transition.mask,
                witness: &transition.witness,
            })
            .collect::<Vec<_>>();

        let materialized_scratch = ScratchDirectory::create();
        let (model, prepared_model) = prepared_fixed_model_fixture(
            &fixture,
            &setup,
            ARTIFACT_VARIABLES,
            &materialized_scratch.0,
        );
        let materialized_matrix_inputs = fixture
            .matrices
            .iter()
            .zip(prepared_model.weight_banks())
            .map(|(matrix, weight)| BlsDoryPrecommittedMatrixProverInput {
                statement: fixture.matrix_statement,
                activations: &matrix.activations,
                weight,
                accumulators: &matrix.accumulators,
            })
            .collect::<Vec<_>>();
        let materialized_prepared =
            prepare_bls_dory_shared_layout_with_precommitted_weights_at_variables_with_scratch(
                b"artifact-shared-layout",
                &model,
                prepared_model.identity(),
                &materialized_matrix_inputs,
                &transition_inputs,
                fixture.wiring_statement,
                &fixture.initial,
                &fixture.inputs,
                &fixture.outputs,
                ARTIFACT_VARIABLES,
                &setup,
                &materialized_scratch.0,
            )
            .unwrap();
        let materialized_components = materialized_prepared.proof.clone();
        let materialized_proof = finish_prepared_shared_layout(
            materialized_prepared,
            &setup,
            Some(&materialized_scratch.0),
        )
        .unwrap();
        drop(materialized_matrix_inputs);
        drop(prepared_model);
        assert_eq!(
            std::fs::read_dir(&materialized_scratch.0).unwrap().count(),
            0
        );

        let artifact_scratch = ScratchDirectory::create();
        let (artifact_model, artifact_prepared_model) =
            prepared_fixed_model_fixture(&fixture, &setup, ARTIFACT_VARIABLES, &artifact_scratch.0);
        assert_eq!(artifact_model, model);
        let artifact_fixed_model = artifact_prepared_model.identity().clone();
        let context = BlsDoryExecutionAccumulatorArtifactContext::for_test(
            [[0x81; 32], [0x82; 32], setup.identity(), challenge],
            fixture.wiring_statement.rows,
            fixture.wiring_statement.cols,
            fixture.wiring_statement.banks,
            fixture.wiring_statement.layers_per_bank,
            2,
        )
        .unwrap();
        let mut artifact =
            execution_artifact_for_linked_fixture(&fixture, context, &artifact_scratch.0);

        let wrong_mask = StructuredMaskPolynomial::from_challenge_at_layer_offset(
            &[0x6b; 32],
            0,
            fixture.wiring_statement.layers_per_bank,
            fixture.wiring_statement.rows,
            fixture.wiring_statement.cols,
        )
        .unwrap();
        let mut wrong_masks = masks.clone();
        wrong_masks[1] = &wrong_mask;
        let entries_before_rejection = std::fs::read_dir(&artifact_scratch.0).unwrap().count();
        assert!(matches!(
            prepare_bls_dory_shared_layout_from_execution_artifact_with_scratch(
                b"artifact-shared-layout",
                &artifact_model,
                &artifact_prepared_model,
                &matrix_statements,
                &transition_statements,
                &wrong_masks,
                fixture.wiring_statement,
                &mut artifact,
                context,
                ARTIFACT_VARIABLES,
                &setup,
                &artifact_scratch.0,
            ),
            Err(BlsDorySharedLayoutError::ExecutionArtifact)
        ));
        assert_eq!(
            std::fs::read_dir(&artifact_scratch.0).unwrap().count(),
            entries_before_rejection
        );

        let artifact_prepared =
            prepare_bls_dory_shared_layout_from_execution_artifact_with_scratch(
                b"artifact-shared-layout",
                &artifact_model,
                &artifact_prepared_model,
                &matrix_statements,
                &transition_statements,
                &masks,
                fixture.wiring_statement,
                &mut artifact,
                context,
                ARTIFACT_VARIABLES,
                &setup,
                &artifact_scratch.0,
            )
            .unwrap();
        assert_eq!(artifact_prepared.proof, materialized_components);
        let final_activation = extract_bls_dory_final_activation_from_execution_artifact(
            *transition_statements.last().unwrap(),
            masks.last().unwrap(),
            &mut artifact,
            context,
        )
        .unwrap();
        let cells = fixture.wiring_statement.rows * fixture.wiring_statement.cols;
        let expected_activation = fixture.outputs[fixture.outputs.len() - cells..]
            .iter()
            .copied()
            .map(|value| u8::try_from(value + 125).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(final_activation, expected_activation);

        // The prepared state owns all capabilities needed by aggregation.
        drop(artifact);
        drop(artifact_prepared_model);
        let artifact_proof =
            finish_prepared_shared_layout(artifact_prepared, &setup, Some(&artifact_scratch.0))
                .unwrap();
        assert_eq!(artifact_proof, materialized_proof);
        assert_eq!(std::fs::read_dir(&artifact_scratch.0).unwrap().count(), 0);
        verify_bls_dory_shared_layout_at_variables(
            b"artifact-shared-layout",
            &artifact_model,
            &artifact_fixed_model,
            &matrix_statements,
            &transition_statements,
            &masks,
            fixture.wiring_statement,
            &artifact_proof,
            ARTIFACT_VARIABLES,
            &setup,
        )
        .unwrap();
    }

    #[test]
    fn scalar_components_share_one_opening_payload() {
        let setup = deterministic_bls_dory_setup(FIXTURE_VARIABLES).unwrap();
        let fixture = linked_fixture(1);
        let (model, fixed_model) = fixed_model_fixture(&fixture, &setup);
        let matrix_statements = vec![fixture.matrix_statement; fixture.matrices.len()];
        let transition_statements = fixture
            .transitions
            .iter()
            .map(|transition| transition.statement)
            .collect::<Vec<_>>();
        let masks = fixture
            .transitions
            .iter()
            .map(|transition| &transition.mask)
            .collect::<Vec<_>>();
        let matrix_inputs = fixture
            .matrices
            .iter()
            .map(|matrix| BlsDoryMatrixProverInput {
                statement: fixture.matrix_statement,
                activations: &matrix.activations,
                weights: &matrix.weights,
                accumulators: &matrix.accumulators,
            })
            .collect::<Vec<_>>();
        let transition_inputs = fixture
            .transitions
            .iter()
            .map(|transition| BlsDoryTransitionProverInput {
                statement: transition.statement,
                mask_polynomial: &transition.mask,
                witness: &transition.witness,
            })
            .collect::<Vec<_>>();
        let proof = prove_bls_dory_shared_layout_at_variables(
            b"shared-opening",
            &model,
            &fixed_model,
            &matrix_inputs,
            &transition_inputs,
            fixture.wiring_statement,
            &fixture.initial,
            &fixture.inputs,
            &fixture.outputs,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();
        let scratch = ScratchDirectory::create();
        let scratch_proof = prove_bls_dory_shared_layout_at_variables_with_scratch(
            b"shared-opening",
            &model,
            &fixed_model,
            &matrix_inputs,
            &transition_inputs,
            fixture.wiring_statement,
            &fixture.initial,
            &fixture.inputs,
            &fixture.outputs,
            FIXTURE_VARIABLES,
            &setup,
            &scratch.0,
        )
        .unwrap();
        assert_eq!(scratch_proof, proof);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
        let precommitted_weights = fixture
            .matrices
            .iter()
            .map(|matrix| {
                commit_fixed_table_with_optional_scratch(
                    &matrix.weights,
                    FIXTURE_VARIABLES,
                    &setup,
                    Some(&scratch.0),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let precommitted_inputs = matrix_inputs
            .iter()
            .zip(&precommitted_weights)
            .map(|(input, weight)| BlsDoryPrecommittedMatrixProverInput {
                statement: input.statement,
                activations: input.activations,
                weight,
                accumulators: input.accumulators,
            })
            .collect::<Vec<_>>();
        let precommitted_proof =
            prove_bls_dory_shared_layout_with_precommitted_weights_at_variables_with_scratch(
                b"shared-opening",
                &model,
                &fixed_model,
                &precommitted_inputs,
                &transition_inputs,
                fixture.wiring_statement,
                &fixture.initial,
                &fixture.inputs,
                &fixture.outputs,
                FIXTURE_VARIABLES,
                &setup,
                &scratch.0,
            )
            .unwrap();
        assert_eq!(precommitted_proof, proof);
        let prepared_precommitted =
            prepare_bls_dory_shared_layout_with_precommitted_weights_at_variables_with_scratch(
                b"shared-opening",
                &model,
                &fixed_model,
                &precommitted_inputs,
                &transition_inputs,
                fixture.wiring_statement,
                &fixture.initial,
                &fixture.inputs,
                &fixture.outputs,
                FIXTURE_VARIABLES,
                &setup,
                &scratch.0,
            )
            .unwrap();
        assert!(prepared_precommitted.proof.opening_proof.is_empty());
        assert_eq!(
            prepared_precommitted
                .pending_final_output()
                .signed_evaluation(),
            proof.final_output_evaluation
        );
        let split_precommitted_proof =
            finish_prepared_shared_layout(prepared_precommitted, &setup, Some(&scratch.0)).unwrap();
        assert_eq!(split_precommitted_proof, proof);
        drop(precommitted_inputs);
        let mut wrong_values = fixture.matrices[0].weights.clone();
        wrong_values[0] += 1;
        let wrong_weight = commit_fixed_table_with_optional_scratch(
            &wrong_values,
            FIXTURE_VARIABLES,
            &setup,
            Some(&scratch.0),
        )
        .unwrap();
        let wrong_inputs = matrix_inputs
            .iter()
            .enumerate()
            .map(|(index, input)| BlsDoryPrecommittedMatrixProverInput {
                statement: input.statement,
                activations: input.activations,
                weight: if index == 0 {
                    &wrong_weight
                } else {
                    &precommitted_weights[index]
                },
                accumulators: input.accumulators,
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            prepare_bls_dory_shared_layout_with_precommitted_weights_at_variables_with_scratch(
                b"shared-opening",
                &model,
                &fixed_model,
                &wrong_inputs,
                &transition_inputs,
                fixture.wiring_statement,
                &fixture.initial,
                &fixture.inputs,
                &fixture.outputs,
                FIXTURE_VARIABLES,
                &setup,
                &scratch.0,
            ),
            Err(BlsDorySharedLayoutError::FixedModelCommitment)
        ));
        drop(wrong_inputs);
        drop(wrong_weight);
        drop(precommitted_weights);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
        verify_bls_dory_shared_layout_at_variables(
            b"shared-opening",
            &model,
            &fixed_model,
            &matrix_statements,
            &transition_statements,
            &masks,
            fixture.wiring_statement,
            &proof,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();

        let encoded = proof
            .encode(
                &matrix_statements,
                &transition_statements,
                fixture.wiring_statement,
            )
            .unwrap();
        assert_eq!(encoded.len(), 35_989);
        assert_eq!(
            blake3::hash(&encoded).to_hex().as_str(),
            "6c5dae3e431d41b88f8f49c2bcdc4c598578d1975e49190bad9f19e70dbb3e83"
        );
        let decoded = BlsDorySharedLayoutProof::decode_with_variables(
            &encoded,
            &matrix_statements,
            &transition_statements,
            fixture.wiring_statement,
            FIXTURE_VARIABLES,
        )
        .unwrap();
        assert_eq!(decoded, proof);
        crate::dory_bls12_381_candidate::verify_algebraic_payload(
            b"shared-opening",
            &model,
            &fixed_model,
            &matrix_statements,
            &transition_statements,
            &masks,
            fixture.wiring_statement,
            &encoded,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();
        assert!(
            crate::dory_bls12_381_candidate::verify_algebraic_payload(
                b"replayed-binding",
                &model,
                &fixed_model,
                &matrix_statements,
                &transition_statements,
                &masks,
                fixture.wiring_statement,
                &encoded,
                FIXTURE_VARIABLES,
                &setup,
            )
            .is_err()
        );
        let mut substituted = encoded.clone();
        let last = substituted.len() - 1;
        substituted[last] ^= 1;
        assert!(
            crate::dory_bls12_381_candidate::verify_algebraic_payload(
                b"shared-opening",
                &model,
                &fixed_model,
                &matrix_statements,
                &transition_statements,
                &masks,
                fixture.wiring_statement,
                &substituted,
                FIXTURE_VARIABLES,
                &setup,
            )
            .is_err()
        );
        verify_bls_dory_shared_layout_at_variables(
            b"shared-opening",
            &model,
            &fixed_model,
            &matrix_statements,
            &transition_statements,
            &masks,
            fixture.wiring_statement,
            &decoded,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();

        assert!(proof.matrices[0].opening_proof.is_empty());
        assert!(proof.transitions[0].arithmetic.opening_proof.is_empty());
        assert!(proof.transitions[0].range.opening_proof.is_empty());
        assert!(proof.transitions[1].arithmetic.opening_proof.is_empty());
        assert!(proof.transitions[1].range.opening_proof.is_empty());
        assert!(proof.wiring.opening_proof.is_empty());
        assert_eq!(proof.link_evaluations.len(), 5);
        assert_eq!(proof.opening_proof.len(), 21_775);

        let mut malformed = encoded.clone();
        malformed[0] ^= 1;
        assert!(
            BlsDorySharedLayoutProof::decode_with_variables(
                &malformed,
                &matrix_statements,
                &transition_statements,
                fixture.wiring_statement,
                FIXTURE_VARIABLES,
            )
            .is_err()
        );
        let mut malformed = encoded.clone();
        malformed[16..20].copy_from_slice(&0_u32.to_le_bytes());
        assert!(
            BlsDorySharedLayoutProof::decode_with_variables(
                &malformed,
                &matrix_statements,
                &transition_statements,
                fixture.wiring_statement,
                FIXTURE_VARIABLES,
            )
            .is_err()
        );
        let mut link_frame_offset = SHARED_PROOF_HEADER_BYTES;
        for _ in 0..matrix_statements.len() + 2 * transition_statements.len() + 1 {
            let frame_bytes = read_u32(&encoded, link_frame_offset).unwrap() as usize;
            link_frame_offset += 4 + frame_bytes;
        }
        let link_frame_bytes = read_u32(&encoded, link_frame_offset).unwrap() as usize;
        let final_output_frame_offset = link_frame_offset + 4 + link_frame_bytes;
        assert_eq!(
            read_u32(&encoded, final_output_frame_offset).unwrap() as usize,
            BlsDoryFr::zero().compressed_size()
        );
        let mut malformed = encoded.clone();
        malformed[link_frame_offset..link_frame_offset + 4].copy_from_slice(&0_u32.to_le_bytes());
        assert!(
            BlsDorySharedLayoutProof::decode_with_variables(
                &malformed,
                &matrix_statements,
                &transition_statements,
                fixture.wiring_statement,
                FIXTURE_VARIABLES,
            )
            .is_err()
        );
        let mut malformed = encoded.clone();
        malformed[final_output_frame_offset..final_output_frame_offset + 4]
            .copy_from_slice(&31_u32.to_le_bytes());
        assert!(
            BlsDorySharedLayoutProof::decode_with_variables(
                &malformed,
                &matrix_statements,
                &transition_statements,
                fixture.wiring_statement,
                FIXTURE_VARIABLES,
            )
            .is_err()
        );
        let mut malformed = encoded.clone();
        malformed.remove(final_output_frame_offset + 4 + 31);
        assert!(
            BlsDorySharedLayoutProof::decode_with_variables(
                &malformed,
                &matrix_statements,
                &transition_statements,
                fixture.wiring_statement,
                FIXTURE_VARIABLES,
            )
            .is_err()
        );
        let mut malformed = encoded.clone();
        malformed.push(0);
        assert!(
            BlsDorySharedLayoutProof::decode_with_variables(
                &malformed,
                &matrix_statements,
                &transition_statements,
                fixture.wiring_statement,
                FIXTURE_VARIABLES,
            )
            .is_err()
        );

        let mut changed = proof.clone();
        changed.link_evaluations[0] = changed.link_evaluations[0] + BlsDoryFr::one();
        assert!(
            verify_bls_dory_shared_layout_at_variables(
                b"shared-opening",
                &model,
                &fixed_model,
                &matrix_statements,
                &transition_statements,
                &masks,
                fixture.wiring_statement,
                &changed,
                FIXTURE_VARIABLES,
                &setup,
            )
            .is_err()
        );

        let mut wrong_model = model.clone();
        wrong_model.model_byte_root[0] ^= 1;
        assert_eq!(
            verify_bls_dory_shared_layout_at_variables(
                b"shared-opening",
                &wrong_model,
                &fixed_model,
                &matrix_statements,
                &transition_statements,
                &masks,
                fixture.wiring_statement,
                &proof,
                FIXTURE_VARIABLES,
                &setup,
            ),
            Err(BlsDorySharedLayoutError::FixedModelIdentity)
        );

        let mut wrong_weight = fixed_model.clone();
        wrong_weight.weight_bank_commitments[0] =
            wrong_weight.weight_bank_commitments[0].scale(&BlsDoryFr::from_u64(2));
        assert_eq!(
            verify_bls_dory_shared_layout_at_variables(
                b"shared-opening",
                &model,
                &wrong_weight,
                &matrix_statements,
                &transition_statements,
                &masks,
                fixture.wiring_statement,
                &proof,
                FIXTURE_VARIABLES,
                &setup,
            ),
            Err(BlsDorySharedLayoutError::FixedModelCommitment)
        );

        let mut wrong_base = fixed_model.clone();
        wrong_base.base_input_commitment = wrong_base
            .base_input_commitment
            .scale(&BlsDoryFr::from_u64(2));
        assert!(
            verify_bls_dory_shared_layout_at_variables(
                b"shared-opening",
                &model,
                &wrong_base,
                &matrix_statements,
                &transition_statements,
                &masks,
                fixture.wiring_statement,
                &proof,
                FIXTURE_VARIABLES,
                &setup,
            )
            .is_err()
        );

        let mut changed = proof.clone();
        let middle = changed.opening_proof.len() / 2;
        changed.opening_proof[middle] ^= 1;
        assert!(
            verify_bls_dory_shared_layout_at_variables(
                b"shared-opening",
                &model,
                &fixed_model,
                &matrix_statements,
                &transition_statements,
                &masks,
                fixture.wiring_statement,
                &changed,
                FIXTURE_VARIABLES,
                &setup,
            )
            .is_err()
        );

        let mut changed = proof.clone();
        changed.matrices[0].transcript_digest[0] ^= 1;
        assert!(
            verify_bls_dory_shared_layout_at_variables(
                b"shared-opening",
                &model,
                &fixed_model,
                &matrix_statements,
                &transition_statements,
                &masks,
                fixture.wiring_statement,
                &changed,
                FIXTURE_VARIABLES,
                &setup,
            )
            .is_err()
        );

        let mut changed = proof.clone();
        changed.transitions[0].range.transition_commitment =
            changed.transitions[0].range.multiplicity_commitment;
        assert_eq!(
            verify_bls_dory_shared_layout_at_variables(
                b"shared-opening",
                &model,
                &fixed_model,
                &matrix_statements,
                &transition_statements,
                &masks,
                fixture.wiring_statement,
                &changed,
                FIXTURE_VARIABLES,
                &setup,
            ),
            Err(BlsDorySharedLayoutError::TransitionRangeCommitment)
        );

        let mut changed = proof.clone();
        changed.wiring.opening_proof.push(0);
        assert_eq!(
            verify_bls_dory_shared_layout_at_variables(
                b"shared-opening",
                &model,
                &fixed_model,
                &matrix_statements,
                &transition_statements,
                &masks,
                fixture.wiring_statement,
                &changed,
                FIXTURE_VARIABLES,
                &setup,
            ),
            Err(BlsDorySharedLayoutError::InvalidProofShape)
        );
        assert!(
            verify_bls_dory_shared_layout_at_variables(
                b"other-binding",
                &model,
                &fixed_model,
                &matrix_statements,
                &transition_statements,
                &masks,
                fixture.wiring_statement,
                &proof,
                FIXTURE_VARIABLES,
                &setup,
            )
            .is_err()
        );
    }

    #[cfg(feature = "whir-prototype")]
    #[test]
    fn dory_final_output_and_blake3_argument_share_exact_activation_bytes() {
        const PADDED_VARIABLES: usize = 13;
        let setup = deterministic_bls_dory_setup(PADDED_VARIABLES).unwrap();
        let fixture = linked_fixture_shape(1, 2, 4, 8);
        let (model, fixed_model) =
            fixed_model_fixture_at_variables(&fixture, &setup, PADDED_VARIABLES);
        let matrix_statements = vec![fixture.matrix_statement; fixture.matrices.len()];
        let transition_statements = fixture
            .transitions
            .iter()
            .map(|transition| transition.statement)
            .collect::<Vec<_>>();
        let masks = fixture
            .transitions
            .iter()
            .map(|transition| &transition.mask)
            .collect::<Vec<_>>();
        let matrix_inputs = fixture
            .matrices
            .iter()
            .map(|matrix| BlsDoryMatrixProverInput {
                statement: fixture.matrix_statement,
                activations: &matrix.activations,
                weights: &matrix.weights,
                accumulators: &matrix.accumulators,
            })
            .collect::<Vec<_>>();
        let transition_inputs = fixture
            .transitions
            .iter()
            .map(|transition| BlsDoryTransitionProverInput {
                statement: transition.statement,
                mask_polynomial: &transition.mask,
                witness: &transition.witness,
            })
            .collect::<Vec<_>>();
        let dory_proof = prove_bls_dory_shared_layout_at_variables(
            b"cross-proof-final-output",
            &model,
            &fixed_model,
            &matrix_inputs,
            &transition_inputs,
            fixture.wiring_statement,
            &fixture.initial,
            &fixture.inputs,
            &fixture.outputs,
            PADDED_VARIABLES,
            &setup,
        )
        .unwrap();
        let final_output = verify_bls_dory_shared_layout_with_final_output_at_variables(
            b"cross-proof-final-output",
            &model,
            &fixed_model,
            &matrix_statements,
            &transition_statements,
            &masks,
            fixture.wiring_statement,
            &dory_proof,
            PADDED_VARIABLES,
            &setup,
        )
        .unwrap();

        let final_cells = fixture.wiring_statement.rows * fixture.wiring_statement.cols;
        let final_activation = fixture.outputs[fixture.outputs.len() - final_cells..]
            .iter()
            .map(|value| u8::try_from(*value + 125).unwrap())
            .collect::<Vec<_>>();
        let challenge = [0x91; 32];
        let digest = crate::forgematrix_v2::output_digest(challenge, &final_activation);
        let bridge =
            crate::dory_bls12_381_output_bridge::BlsDoryOutputBridgeStatement::from_verified_dory(
                challenge,
                digest,
                final_activation.len(),
                &final_output,
            )
            .unwrap();
        bridge.validate_activation(&final_activation).unwrap();
        let blake3_proof =
            crate::structured_blake3_narrow::bls_bridge::prove_bls_dory_narrow_blake3(
                &bridge,
                &final_activation,
            )
            .unwrap();
        crate::structured_blake3_narrow::bls_bridge::verify_bls_dory_narrow_blake3(
            &bridge,
            &blake3_proof,
        )
        .unwrap();

        let mut wrong_digest = digest;
        wrong_digest[0] ^= 1;
        let wrong_digest_statement =
            crate::dory_bls12_381_output_bridge::BlsDoryOutputBridgeStatement::from_verified_dory(
                challenge,
                wrong_digest,
                final_activation.len(),
                &final_output,
            )
            .unwrap();
        assert!(
            crate::structured_blake3_narrow::bls_bridge::verify_bls_dory_narrow_blake3(
                &wrong_digest_statement,
                &blake3_proof,
            )
            .is_err()
        );
        let wrong_challenge_statement =
            crate::dory_bls12_381_output_bridge::BlsDoryOutputBridgeStatement::from_verified_dory(
                [0x92; 32],
                digest,
                final_activation.len(),
                &final_output,
            )
            .unwrap();
        assert!(
            crate::structured_blake3_narrow::bls_bridge::verify_bls_dory_narrow_blake3(
                &wrong_challenge_statement,
                &blake3_proof,
            )
            .is_err()
        );
        let mut changed_activation = final_activation;
        changed_activation[7] ^= 1;
        assert!(
            crate::structured_blake3_narrow::bls_bridge::prove_bls_dory_narrow_blake3(
                &bridge,
                &changed_activation,
            )
            .is_err()
        );
    }

    #[test]
    #[ignore = "release-only complete shared-layout scratch and latency benchmark"]
    fn shared_layout_release_scaling_benchmark() {
        const PADDED_VARIABLES: usize = 19;
        const BANKS: usize = 3;
        const LAYERS: usize = 16;
        const ROWS: usize = 8;
        const COLUMNS: usize = 32;

        let fixture_start = std::time::Instant::now();
        let fixture = linked_fixture_shape(BANKS, LAYERS, ROWS, COLUMNS);
        let fixture_millis = fixture_start.elapsed().as_millis();
        let setup_start = std::time::Instant::now();
        let setup = deterministic_bls_dory_setup(PADDED_VARIABLES).unwrap();
        let (model, fixed_model) =
            fixed_model_fixture_at_variables(&fixture, &setup, PADDED_VARIABLES);
        let setup_millis = setup_start.elapsed().as_millis();
        let matrix_statements = vec![fixture.matrix_statement; fixture.matrices.len()];
        let transition_statements = fixture
            .transitions
            .iter()
            .map(|transition| transition.statement)
            .collect::<Vec<_>>();
        let masks = fixture
            .transitions
            .iter()
            .map(|transition| &transition.mask)
            .collect::<Vec<_>>();
        let matrix_inputs = fixture
            .matrices
            .iter()
            .map(|matrix| BlsDoryMatrixProverInput {
                statement: fixture.matrix_statement,
                activations: &matrix.activations,
                weights: &matrix.weights,
                accumulators: &matrix.accumulators,
            })
            .collect::<Vec<_>>();
        let transition_inputs = fixture
            .transitions
            .iter()
            .map(|transition| BlsDoryTransitionProverInput {
                statement: transition.statement,
                mask_polynomial: &transition.mask,
                witness: &transition.witness,
            })
            .collect::<Vec<_>>();
        let scratch = ScratchDirectory::create();
        let stop_observer = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let peak_scratch_bytes = std::sync::Arc::new(AtomicU64::new(0));
        let observer = {
            let path = scratch.0.clone();
            let stop = std::sync::Arc::clone(&stop_observer);
            let peak = std::sync::Arc::clone(&peak_scratch_bytes);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    peak.fetch_max(observed_directory_bytes(&path), Ordering::Relaxed);
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                peak.fetch_max(observed_directory_bytes(&path), Ordering::Relaxed);
            })
        };

        let prover_start = std::time::Instant::now();
        let proof = prove_bls_dory_shared_layout_at_variables_with_scratch(
            b"shared-layout-scaling-benchmark",
            &model,
            &fixed_model,
            &matrix_inputs,
            &transition_inputs,
            fixture.wiring_statement,
            &fixture.initial,
            &fixture.inputs,
            &fixture.outputs,
            PADDED_VARIABLES,
            &setup,
            &scratch.0,
        )
        .unwrap();
        let prover_millis = prover_start.elapsed().as_millis();
        stop_observer.store(true, Ordering::Relaxed);
        observer.join().unwrap();
        let peak_scratch_bytes = peak_scratch_bytes.load(Ordering::Relaxed);
        let projected_scratch = projected_shared_scratch_bytes_for_shape(
            PADDED_VARIABLES,
            BANKS as u64,
            ROWS as u64,
            COLUMNS as u64,
            LAYERS as u64,
            u8::try_from(fixture.matrix_statement.max_abs_activation).unwrap(),
            u8::try_from(fixture.matrix_statement.max_abs_weight).unwrap(),
        )
        .unwrap();

        let verification_start = std::time::Instant::now();
        verify_bls_dory_shared_layout_at_variables(
            b"shared-layout-scaling-benchmark",
            &model,
            &fixed_model,
            &matrix_statements,
            &transition_statements,
            &masks,
            fixture.wiring_statement,
            &proof,
            PADDED_VARIABLES,
            &setup,
        )
        .unwrap();
        let verification_millis = verification_start.elapsed().as_millis();
        let proof_bytes = proof
            .encode(
                &matrix_statements,
                &transition_statements,
                fixture.wiring_statement,
            )
            .unwrap()
            .len();
        let retained_scratch_bytes = observed_directory_bytes(&scratch.0);
        println!(
            "CMFD_BLS_SHARED_BENCHMARK {{\"padded_variables\":{PADDED_VARIABLES},\"banks\":{BANKS},\"layers\":{LAYERS},\"rows\":{ROWS},\"columns\":{COLUMNS},\"fixture_millis\":{fixture_millis},\"setup_millis\":{setup_millis},\"prover_millis\":{prover_millis},\"verification_millis\":{verification_millis},\"proof_bytes\":{proof_bytes},\"peak_scratch_bytes\":{peak_scratch_bytes},\"projected_aggregate_scratch_bytes\":{},\"retained_scratch_bytes\":{retained_scratch_bytes}}}",
            projected_scratch.aggregate_peak_bytes
        );
        assert_eq!(proof.matrices.len(), BANKS);
        assert_eq!(proof.transitions.len(), BANKS + 1);
        assert!(peak_scratch_bytes >= projected_scratch.aggregate_peak_bytes);
        assert_eq!(retained_scratch_bytes, 0);
    }

    #[test]
    fn transition_range_composition_requires_both_proofs_and_one_commitment() {
        let setup = deterministic_bls_dory_setup(FIXTURE_VARIABLES).unwrap();
        let (statement, mask, witness) = transition_fixture();
        let proof =
            prove_bls_dory_transition_range(b"composed", statement, &mask, &witness, &setup)
                .unwrap();
        verify_bls_dory_transition_range(b"composed", statement, &mask, &proof, &setup).unwrap();

        let mut mismatched = proof.clone();
        mismatched.range.transition_commitment = mismatched.range.multiplicity_commitment;
        assert_eq!(
            verify_bls_dory_transition_range(b"composed", statement, &mask, &mismatched, &setup,),
            Err(BlsDorySharedLayoutError::TransitionRangeCommitment)
        );

        let mut missing_range = proof;
        missing_range.range.opening_proof[0] ^= 1;
        assert!(
            verify_bls_dory_transition_range(
                b"composed",
                statement,
                &mask,
                &missing_range,
                &setup,
            )
            .is_err()
        );
    }

    #[test]
    fn production_component_counts_share_one_payload() {
        let setup = deterministic_bls_dory_setup(FIXTURE_VARIABLES).unwrap();
        let fixture = linked_fixture(3);
        let (model, fixed_model) = fixed_model_fixture(&fixture, &setup);
        let matrix_statements = vec![fixture.matrix_statement; fixture.matrices.len()];
        let transition_statements = fixture
            .transitions
            .iter()
            .map(|transition| transition.statement)
            .collect::<Vec<_>>();
        let masks = fixture
            .transitions
            .iter()
            .map(|transition| &transition.mask)
            .collect::<Vec<_>>();
        let matrix_inputs = fixture
            .matrices
            .iter()
            .map(|matrix| BlsDoryMatrixProverInput {
                statement: fixture.matrix_statement,
                activations: &matrix.activations,
                weights: &matrix.weights,
                accumulators: &matrix.accumulators,
            })
            .collect::<Vec<_>>();
        let transition_inputs = fixture
            .transitions
            .iter()
            .map(|transition| BlsDoryTransitionProverInput {
                statement: transition.statement,
                mask_polynomial: &transition.mask,
                witness: &transition.witness,
            })
            .collect::<Vec<_>>();
        let proof = prove_bls_dory_shared_layout_at_variables(
            b"production-topology",
            &model,
            &fixed_model,
            &matrix_inputs,
            &transition_inputs,
            fixture.wiring_statement,
            &fixture.initial,
            &fixture.inputs,
            &fixture.outputs,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();
        let final_output = verify_bls_dory_shared_layout_with_final_output_at_variables(
            b"production-topology",
            &model,
            &fixed_model,
            &matrix_statements,
            &transition_statements,
            &masks,
            fixture.wiring_statement,
            &proof,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();
        assert_eq!(
            final_output.cell_point().len(),
            (fixture.wiring_statement.rows * fixture.wiring_statement.cols).ilog2() as usize
        );
        assert_eq!(
            final_output.signed_evaluation(),
            proof.final_output_evaluation
        );
        assert_ne!(final_output.transcript_binding(), [0; 32]);
        assert_eq!(proof.matrices.len(), 3);
        assert_eq!(proof.transitions.len(), 4);
        assert_eq!(proof.link_evaluations.len(), 11);
        assert_eq!(proof.opening_proof.len(), 21_775);
        assert_eq!(3 * 3 + 4 * (12 + 4) + 13 + 22 + 2, 110);

        let encoded = proof
            .encode(
                &matrix_statements,
                &transition_statements,
                fixture.wiring_statement,
            )
            .unwrap();
        let decoded = BlsDorySharedLayoutProof::decode_with_variables(
            &encoded,
            &matrix_statements,
            &transition_statements,
            fixture.wiring_statement,
            FIXTURE_VARIABLES,
        )
        .unwrap();
        assert_eq!(decoded, proof);

        let mut changed_final_output = proof.clone();
        changed_final_output.final_output_evaluation =
            changed_final_output.final_output_evaluation + BlsDoryFr::one();
        assert!(
            verify_bls_dory_shared_layout_at_variables(
                b"production-topology",
                &model,
                &fixed_model,
                &matrix_statements,
                &transition_statements,
                &masks,
                fixture.wiring_statement,
                &changed_final_output,
                FIXTURE_VARIABLES,
                &setup,
            )
            .is_err()
        );

        let mut reordered = proof.clone();
        reordered.matrices.swap(0, 1);
        assert!(
            verify_bls_dory_shared_layout_at_variables(
                b"production-topology",
                &model,
                &fixed_model,
                &matrix_statements,
                &transition_statements,
                &masks,
                fixture.wiring_statement,
                &reordered,
                FIXTURE_VARIABLES,
                &setup,
            )
            .is_err()
        );

        let mut omitted = proof;
        omitted.matrices.pop();
        assert!(
            verify_bls_dory_shared_layout_at_variables(
                b"production-topology",
                &model,
                &fixed_model,
                &matrix_statements,
                &transition_statements,
                &masks,
                fixture.wiring_statement,
                &omitted,
                FIXTURE_VARIABLES,
                &setup,
            )
            .is_err()
        );
    }

    #[test]
    fn shared_layout_mismatches_fail_before_opening_verification() {
        let setup = deterministic_bls_dory_setup(FIXTURE_VARIABLES).unwrap();
        let mismatched_variables = FIXTURE_VARIABLES - 1;

        let (matrix_statement, activations, weights, accumulators) = matrix_fixture();
        let matrix = prove_bls_dory_matrix_at_variables(
            b"mismatch",
            matrix_statement,
            &activations,
            &weights,
            &accumulators,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();
        assert!(
            verify_bls_dory_matrix_at_variables(
                b"mismatch",
                matrix_statement,
                &matrix,
                mismatched_variables,
                &setup,
            )
            .is_err()
        );
        let matrix_encoded = matrix.encode(matrix_statement).unwrap();
        assert!(
            BlsDoryMatrixProof::decode_with_variables(
                &matrix_encoded,
                matrix_statement,
                mismatched_variables,
            )
            .is_err()
        );

        let (transition_statement, mask, witness) = transition_fixture();
        let transition = prove_bls_dory_transition_at_variables(
            b"mismatch",
            transition_statement,
            &mask,
            &witness,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();
        assert!(
            verify_bls_dory_transition_at_variables(
                b"mismatch",
                transition_statement,
                &mask,
                &transition,
                mismatched_variables,
                &setup,
            )
            .is_err()
        );
        let transition_encoded = transition.encode(transition_statement).unwrap();
        assert!(
            BlsDoryTransitionProof::decode_with_variables(
                &transition_encoded,
                transition_statement,
                mismatched_variables,
            )
            .is_err()
        );

        let (wiring_statement, initial, inputs, outputs) = wiring_fixture();
        let wiring = prove_bls_dory_wiring_at_variables(
            b"mismatch",
            wiring_statement,
            &initial,
            &inputs,
            &outputs,
            FIXTURE_VARIABLES,
            &setup,
        )
        .unwrap();
        assert!(
            verify_bls_dory_wiring_at_variables(
                b"mismatch",
                wiring_statement,
                &wiring,
                mismatched_variables,
                &setup,
            )
            .is_err()
        );
        let wiring_encoded = wiring.encode(wiring_statement).unwrap();
        assert!(
            BlsDoryWiringProof::decode_with_variables(
                &wiring_encoded,
                wiring_statement,
                mismatched_variables,
            )
            .is_err()
        );
    }

    #[test]
    fn production_claim_accounting_and_shared_projection_are_explicit() {
        let scratch = projected_shared_production_scratch_bytes().unwrap();
        assert_eq!(scratch.matrix_source_bytes, 8_259_944_736);
        assert_eq!(scratch.transition_source_bytes, 17_157_327_360);
        assert_eq!(scratch.multiplicity_source_bytes, 2_576);
        assert_eq!(scratch.wiring_source_bytes, 470_687_712);
        assert_eq!(scratch.fixed_base_source_bytes, 16_777_348);
        assert_eq!(scratch.retained_source_bytes, 25_904_739_732);
        assert_eq!(scratch.matrix_first_fold_bytes, 0);
        assert_eq!(scratch.transition_first_fold_bytes, 0);
        assert_eq!(scratch.multiplicity_first_fold_bytes, 1_552);
        assert_eq!(scratch.wiring_first_fold_bytes, 0);
        assert_eq!(scratch.fixed_base_first_fold_bytes, 8_388_740);
        assert_eq!(scratch.first_generation_fold_bytes, 8_390_292);
        assert_eq!(scratch.fifth_generation_fold_bytes, 525_076);
        assert_eq!(scratch.source_materialization_fold_bytes, 3_232_664_668);
        assert_eq!(scratch.aggregate_fold_peak_bytes, 3_297_676_512);
        assert_eq!(scratch.aggregate_peak_bytes, 29_202_416_244);
        assert_eq!(BLS_DORY_SHARED_PRODUCTION_VARIABLES, 33);
        assert_eq!(BLS_DORY_SHARED_PRODUCTION_DIRECT_CLAIMS, 480);
        assert_eq!(BLS_DORY_SHARED_ARITHMETIC_TRANSITION_CLAIMS, 48);
        assert_eq!(BLS_DORY_SHARED_LOGUP_RANGE_TRANSITION_CLAIMS, 16);
        assert_eq!(BLS_DORY_SHARED_COMPRESSED_TRANSITION_CLAIMS, 64);
        assert_eq!(BLS_DORY_SHARED_COMPRESSED_CHECKPOINT_CLAIMS, 104);
        assert_eq!(BLS_DORY_SHARED_PRODUCTION_EQUALITY_LINKS, 11);
        assert_eq!(BLS_DORY_SHARED_PRODUCTION_EQUALITY_CLAIMS, 22);
        assert_eq!(BLS_DORY_SHARED_FINAL_OUTPUT_BRIDGE_CLAIMS, 2);
        assert_eq!(BLS_DORY_SHARED_PRODUCTION_CLAIMS, 128);
        assert_eq!(MAX_BLS_DORY_AGGREGATE_CLAIMS, 128);
        assert_eq!(projected_shared_production_opening_bytes().unwrap(), 70_639);
        assert_eq!(projected_shared_production_proof_bytes().unwrap(), 133_409);
        assert!(
            projected_shared_production_proof_bytes().unwrap()
                < MAX_BLS_DORY_SHARED_LAYOUT_PROOF_BYTES
        );
        assert_eq!(BLS_DORY_SHARED_LAYOUT_PRODUCTION_BLOCKERS.len(), 2);
        assert_eq!(
            require_bls_dory_shared_layout_production_ready(),
            Err(BlsDorySharedLayoutError::NotProductionReady)
        );
    }

    fn layout_v5_context() -> BlsDorySharedLayoutV5Context {
        BlsDorySharedLayoutV5Context {
            suite_digest: Digest32::new([0x11; 32]),
            model_identity_digest: Digest32::new([0x22; 32]),
            setup_identity: Digest32::new([0x33; 32]),
            padded_variables: 6,
        }
    }

    struct LayoutV5CodecFixture {
        context: BlsDorySharedLayoutV5Context,
        matrix_statements: Vec<StructuredMatrixStatement>,
        transition_statements: Vec<StructuredTransitionStatement>,
        wiring_statement: StructuredWiringStatement,
        proof: BlsDorySharedLayoutV5Proof,
    }

    fn layout_v5_codec_fixture() -> LayoutV5CodecFixture {
        let production = StructuredForgeMatrixResearchShape::production_candidate();
        let matrix_statements = production.matrix_statements.to_vec();
        let mut transition_statements = Vec::with_capacity(MAX_BLS_DORY_SHARED_TRANSITION_PROOFS);
        transition_statements.push(production.initialization_statement);
        transition_statements.extend_from_slice(&production.transition_statements);
        let wiring_statement = production.wiring_statement;
        let padded_variables = u16::try_from(DORY_V3_PADDED_VARIABLES).unwrap();
        let zero = BlsDoryFr::zero();

        let matrices = matrix_statements
            .iter()
            .enumerate()
            .map(|(index, statement)| {
                let common_rounds = statement.inner.ilog2() as usize;
                let layer_rounds = statement.layers.ilog2() as usize;
                let mut rounds = vec![vec![zero; 3]; common_rounds];
                rounds.extend(vec![vec![zero; 4]; layer_rounds]);
                BlsDoryMatrixProof {
                    protocol_version: crate::dory_bls12_381_matrix::BLS_DORY_MATRIX_VERSION,
                    padded_variables,
                    activation_commitment: BlsDoryGt::identity(),
                    weight_commitment: BlsDoryGt::identity(),
                    accumulator_commitment: BlsDoryGt::identity(),
                    accumulator_evaluation: zero,
                    rounds,
                    activation_evaluation: zero,
                    weight_evaluation: zero,
                    transcript_digest: [0x31 + index as u8; 32],
                    opening_proof: Vec::new(),
                }
            })
            .collect::<Vec<_>>();
        let transitions = transition_statements
            .iter()
            .enumerate()
            .map(|(index, statement)| {
                let cell_variables = statement.elements().unwrap().ilog2() as usize;
                BlsDoryTransitionRangeProof {
                    arithmetic: BlsDoryTransitionProof {
                        protocol_version:
                            crate::dory_bls12_381_transition::BLS_DORY_TRANSITION_VERSION,
                        packed_variables: padded_variables,
                        oracle_commitment: BlsDoryGt::identity(),
                        rounds: vec![vec![zero; 4]; cell_variables],
                        terminal_evaluations: vec![zero; BLS_DORY_TRANSITION_OPENING_CLAIMS],
                        transcript_digest: [0x41 + index as u8; 32],
                        opening_proof: Vec::new(),
                    },
                    range: BlsDoryRangeLogUpProof {
                        protocol_version: crate::dory_bls12_381_logup::BLS_DORY_RANGE_LOGUP_VERSION,
                        packed_variables: padded_variables,
                        transition_commitment: BlsDoryGt::identity(),
                        multiplicity_commitment: BlsDoryGt::identity(),
                        inverse_commitment: BlsDoryGt::identity(),
                        rounds: vec![[zero; 5]; DORY_V3_PADDED_VARIABLES as usize],
                        terminal_evaluations: [zero; 3],
                        source_claim: zero,
                        reconstruction_rounds: vec![
                            [zero; 3];
                            crate::dory_bls12_381_logup::BLS_DORY_RANGE_LOGUP_SELECTOR_VARIABLES
                        ],
                        reconstruction_evaluation: zero,
                        transcript_digest: [0x51 + index as u8; 32],
                        opening_proof: Vec::new(),
                    },
                }
            })
            .collect::<Vec<_>>();
        let wiring_evaluations = wiring_statement
            .banks
            .checked_mul(wiring_statement.layers_per_bank.ilog2() as usize + 3)
            .and_then(|count| count.checked_add(1))
            .unwrap();
        let wiring = BlsDoryWiringProof {
            protocol_version: crate::dory_bls12_381_wiring::BLS_DORY_WIRING_VERSION,
            packed_variables: padded_variables,
            oracle_commitment: BlsDoryGt::identity(),
            evaluations: vec![zero; wiring_evaluations],
            transcript_digest: [0x61; 32],
            opening_proof: Vec::new(),
        };
        let context = BlsDorySharedLayoutV5Context {
            suite_digest: *DORY_V3_PRODUCTION_SUITE_DIGEST,
            model_identity_digest: Digest32::new([0x71; 32]),
            setup_identity: DORY_V3_SETUP_IDENTITY,
            padded_variables: DORY_V3_PADDED_VARIABLES,
        };
        let proof = BlsDorySharedLayoutV5Proof {
            context,
            proof: BlsDorySharedLayoutProof {
                protocol_version: DORY_V3_SHARED_LAYOUT_VERSION,
                padded_variables,
                matrices,
                transitions,
                wiring,
                link_evaluations: vec![zero; BLS_DORY_SHARED_PRODUCTION_EQUALITY_LINKS],
                final_output_evaluation: zero,
                opening_proof: vec![0xa5; 17],
            },
        };
        LayoutV5CodecFixture {
            context,
            matrix_statements,
            transition_statements,
            wiring_statement,
            proof,
        }
    }

    #[test]
    fn layout_v5_codec_round_trips_and_versions_do_not_fallback() {
        let fixture = layout_v5_codec_fixture();
        let encoded = fixture
            .proof
            .encode(
                &fixture.matrix_statements,
                &fixture.transition_statements,
                fixture.wiring_statement,
            )
            .unwrap();
        assert_eq!(&encoded[..8], &SHARED_PROOF_MAGIC);
        assert_eq!(
            read_u16(&encoded, 8).unwrap(),
            DORY_V3_SHARED_LAYOUT_VERSION
        );
        assert_eq!(read_u16(&encoded, 10).unwrap(), 33);
        assert_eq!(read_u16(&encoded, 12).unwrap(), 3);
        assert_eq!(read_u16(&encoded, 14).unwrap(), 4);
        assert_eq!(encoded.len(), 61_891);
        assert_eq!(
            digest_hex(*blake3::hash(&encoded).as_bytes()),
            "5db680d138663ffaa6e5c9a2e7d44c026956bf1f5d43ce4b200471565460dc9d"
        );
        assert_eq!(
            BlsDorySharedLayoutV5Proof::decode_with_context(
                &encoded,
                &fixture.context,
                &fixture.matrix_statements,
                &fixture.transition_statements,
                fixture.wiring_statement,
            )
            .unwrap(),
            fixture.proof
        );
        assert!(
            BlsDorySharedLayoutProof::decode_with_variables(
                &encoded,
                &fixture.matrix_statements,
                &fixture.transition_statements,
                fixture.wiring_statement,
                BLS_DORY_SHARED_PRODUCTION_VARIABLES,
            )
            .is_err()
        );

        let mut v4 = fixture.proof.proof.clone();
        v4.protocol_version = BLS_DORY_SHARED_LAYOUT_VERSION;
        let encoded_v4 = v4
            .encode(
                &fixture.matrix_statements,
                &fixture.transition_statements,
                fixture.wiring_statement,
            )
            .unwrap();
        assert!(
            BlsDorySharedLayoutV5Proof::decode_with_context(
                &encoded_v4,
                &fixture.context,
                &fixture.matrix_statements,
                &fixture.transition_statements,
                fixture.wiring_statement,
            )
            .is_err()
        );
    }

    #[test]
    fn layout_v5_codec_rejects_wrong_context_version_counts_and_variables() {
        let fixture = layout_v5_codec_fixture();
        let encoded = fixture
            .proof
            .encode(
                &fixture.matrix_statements,
                &fixture.transition_statements,
                fixture.wiring_statement,
            )
            .unwrap();
        let decode = |candidate: &[u8], context: &BlsDorySharedLayoutV5Context| {
            BlsDorySharedLayoutV5Proof::decode_with_context(
                candidate,
                context,
                &fixture.matrix_statements,
                &fixture.transition_statements,
                fixture.wiring_statement,
            )
        };

        let mut wrong_context = fixture.context;
        wrong_context.model_identity_digest = Digest32::ZERO;
        assert_eq!(
            decode(&encoded, &wrong_context),
            Err(BlsDorySharedLayoutError::V3Context)
        );
        for (offset, replacement) in [
            (8, 4_u16),
            (8, 6_u16),
            (10, 32_u16),
            (12, 2_u16),
            (14, 3_u16),
        ] {
            let mut malformed = encoded.clone();
            malformed[offset..offset + 2].copy_from_slice(&replacement.to_le_bytes());
            assert!(decode(&malformed, &fixture.context).is_err());
        }
    }

    #[test]
    fn layout_v5_codec_rejects_trailing_truncated_and_malformed_frames() {
        let fixture = layout_v5_codec_fixture();
        let encoded = fixture
            .proof
            .encode(
                &fixture.matrix_statements,
                &fixture.transition_statements,
                fixture.wiring_statement,
            )
            .unwrap();
        let decode = |candidate: &[u8]| {
            BlsDorySharedLayoutV5Proof::decode_with_context(
                candidate,
                &fixture.context,
                &fixture.matrix_statements,
                &fixture.transition_statements,
                fixture.wiring_statement,
            )
        };

        let mut wrong_magic = encoded.clone();
        wrong_magic[0] ^= 1;
        assert!(decode(&wrong_magic).is_err());

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode(&trailing).is_err());
        assert!(decode(&encoded[..encoded.len() - 1]).is_err());

        let mut empty_first_frame = encoded.clone();
        empty_first_frame[SHARED_PROOF_HEADER_BYTES..SHARED_PROOF_HEADER_BYTES + 4]
            .copy_from_slice(&0_u32.to_le_bytes());
        assert!(decode(&empty_first_frame).is_err());

        let mut oversized_first_frame = encoded;
        oversized_first_frame[SHARED_PROOF_HEADER_BYTES..SHARED_PROOF_HEADER_BYTES + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode(&oversized_first_frame).is_err());
    }

    #[test]
    fn layout_v5_codec_rejects_topology_valid_nonproduction_statements() {
        let fixture = layout_v5_codec_fixture();
        let encoded = fixture
            .proof
            .encode(
                &fixture.matrix_statements,
                &fixture.transition_statements,
                fixture.wiring_statement,
            )
            .unwrap();
        let tiny = linked_fixture(MAX_BLS_DORY_SHARED_MATRIX_PROOFS);
        let tiny_matrices = vec![tiny.matrix_statement; tiny.matrices.len()];
        let tiny_transitions = tiny
            .transitions
            .iter()
            .map(|transition| transition.statement)
            .collect::<Vec<_>>();
        validate_shared_link_topology(&tiny_matrices, &tiny_transitions, tiny.wiring_statement)
            .unwrap();

        assert_eq!(
            fixture
                .proof
                .encode(&tiny_matrices, &tiny_transitions, tiny.wiring_statement,),
            Err(BlsDorySharedLayoutError::InvalidProofShape)
        );
        assert_eq!(
            BlsDorySharedLayoutV5Proof::decode_with_context(
                &encoded,
                &fixture.context,
                &tiny_matrices,
                &tiny_transitions,
                tiny.wiring_statement,
            ),
            Err(BlsDorySharedLayoutError::InvalidProofShape)
        );
    }

    fn digest_hex(digest: [u8; 32]) -> String {
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn layout_v5_context_requires_a_bank_authenticated_record() {
        let constructor: fn(
            &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
            &DeterministicBlsDorySetup,
        )
            -> Result<BlsDorySharedLayoutV5Context, BlsDorySharedLayoutError> =
            BlsDorySharedLayoutV5Context::from_bank_authenticated_record;
        let _ = constructor;

        assert_eq!(BLS_DORY_SHARED_LAYOUT_VERSION, 4);
        assert_eq!(DORY_V3_SHARED_LAYOUT_VERSION, 5);
        assert_eq!(DORY_V3_FIXED_MODEL_BINDING_VERSION, 2);
    }

    #[test]
    fn fixed_model_binding_v2_is_exact_and_context_bound() {
        let context = layout_v5_context();
        let binding = context.fixed_model_binding(b"outer-binding").unwrap();

        assert_eq!(
            digest_hex(binding.into_bytes()),
            "d21685b8b19c9fd45195c6449ef749700565fdd8b632ae000b42348615e52fac"
        );
        assert_eq!(
            binding,
            context.fixed_model_binding(b"outer-binding").unwrap()
        );
        assert_ne!(
            binding,
            context.fixed_model_binding(b"outer-bindinh").unwrap()
        );

        let mut changed = context;
        changed.suite_digest = Digest32::new([0x12; 32]);
        assert_ne!(
            binding,
            changed.fixed_model_binding(b"outer-binding").unwrap()
        );
        let mut changed = context;
        changed.model_identity_digest = Digest32::new([0x23; 32]);
        assert_ne!(
            binding,
            changed.fixed_model_binding(b"outer-binding").unwrap()
        );
        let mut changed = context;
        changed.setup_identity = Digest32::new([0x34; 32]);
        assert_ne!(
            binding,
            changed.fixed_model_binding(b"outer-binding").unwrap()
        );
        let mut changed = context;
        changed.padded_variables = 7;
        assert_ne!(
            binding,
            changed.fixed_model_binding(b"outer-binding").unwrap()
        );

        assert_eq!(
            context.fixed_model_binding(&vec![0; MAX_SHARED_LAYOUT_BINDING_BYTES + 1]),
            Err(BlsDorySharedLayoutError::InvalidProofShape)
        );
    }

    #[test]
    fn shared_opening_binding_v5_is_exact_ordered_and_fixed_shape() {
        let context = layout_v5_context();
        let component_binding = context.fixed_model_binding(b"outer-binding").unwrap();
        let matrices = [[0x41; 32], [0x42; 32], [0x43; 32]];
        let transitions = [
            ([0x51; 32], [0x61; 32]),
            ([0x52; 32], [0x62; 32]),
            ([0x53; 32], [0x63; 32]),
            ([0x54; 32], [0x64; 32]),
        ];
        let wiring = [0x71; 32];
        let binding = context
            .shared_opening_binding_from_digests(component_binding, &matrices, &transitions, wiring)
            .unwrap();

        assert_eq!(
            digest_hex(binding.into_bytes()),
            "f31c1dc19ec71e176201fa1ad4d4931d59652348edcf0fc3f350784a27eed76d"
        );

        let mut changed_matrices = matrices;
        changed_matrices.swap(0, 1);
        assert_ne!(
            binding,
            context
                .shared_opening_binding_from_digests(
                    component_binding,
                    &changed_matrices,
                    &transitions,
                    wiring,
                )
                .unwrap()
        );
        let mut changed_transitions = transitions;
        changed_transitions[2].1[0] ^= 1;
        assert_ne!(
            binding,
            context
                .shared_opening_binding_from_digests(
                    component_binding,
                    &matrices,
                    &changed_transitions,
                    wiring,
                )
                .unwrap()
        );
        let mut changed_wiring = wiring;
        changed_wiring[0] ^= 1;
        assert_ne!(
            binding,
            context
                .shared_opening_binding_from_digests(
                    component_binding,
                    &matrices,
                    &transitions,
                    changed_wiring,
                )
                .unwrap()
        );
        assert_eq!(
            context.shared_opening_binding_from_digests(
                component_binding,
                &matrices[..2],
                &transitions,
                wiring,
            ),
            Err(BlsDorySharedLayoutError::InvalidProofShape)
        );
        assert_eq!(
            context.shared_opening_binding_from_digests(
                component_binding,
                &matrices,
                &transitions[..3],
                wiring,
            ),
            Err(BlsDorySharedLayoutError::InvalidProofShape)
        );
    }

    #[test]
    fn layout_v4_and_v5_link_challenges_are_domain_separated() {
        let fixture = linked_fixture(1);
        let matrix_statements = vec![fixture.matrix_statement];
        let transition_statements = fixture
            .transitions
            .iter()
            .map(|transition| transition.statement)
            .collect::<Vec<_>>();
        let opening_binding = [0x7b; 32];
        let v4 = derive_shared_link_points(
            BLS_DORY_SHARED_LAYOUT_VERSION,
            &opening_binding,
            &matrix_statements,
            &transition_statements,
            fixture.wiring_statement,
            10,
        )
        .unwrap();
        let v5 = derive_shared_link_points(
            DORY_V3_SHARED_LAYOUT_VERSION,
            &opening_binding,
            &matrix_statements,
            &transition_statements,
            fixture.wiring_statement,
            10,
        )
        .unwrap();
        assert_eq!(v4.len(), v5.len());
        assert_ne!(v4[0].left_point, v5[0].left_point);
        assert_ne!(v4[0].right_point, v5[0].right_point);
        assert!(
            derive_shared_link_points(
                6,
                &opening_binding,
                &matrix_statements,
                &transition_statements,
                fixture.wiring_statement,
                10,
            )
            .is_err()
        );
    }

    #[test]
    fn layout_v5_composition_requires_exact_128_plus_6_claims() {
        assert_eq!(validate_layout_v5_composition_claim_counts(128, 6), Ok(()));
        assert_eq!(BLS_DORY_BLAKE3_COMPOSED_OPENING_CLAIMS, 134);
        for (shared, native) in [(127, 6), (129, 6), (128, 5), (128, 7)] {
            assert_eq!(
                validate_layout_v5_composition_claim_counts(shared, native),
                Err(BlsDorySharedLayoutError::OpeningClaims)
            );
        }
    }

    #[test]
    fn native_composition_binding_v1_is_exact_and_uses_the_canonical_v5_split() {
        let context = layout_v5_context();
        let component_binding = context.fixed_model_binding(b"outer-binding").unwrap();
        let matrices = [[0x41; 32], [0x42; 32], [0x43; 32]];
        let transitions = [
            ([0x51; 32], [0x61; 32]),
            ([0x52; 32], [0x62; 32]),
            ([0x53; 32], [0x63; 32]),
            ([0x54; 32], [0x64; 32]),
        ];
        let shared = context
            .shared_opening_binding_from_digests(
                component_binding,
                &matrices,
                &transitions,
                [0x71; 32],
            )
            .unwrap();
        let native = [0x81; 32];
        let layout = BlsDoryAggregateLayout::new(3, 3).unwrap();
        let binding = context
            .native_composition_binding(shared, native, layout)
            .unwrap();

        assert_eq!(
            digest_hex(binding),
            "8d80f196546910d53a964dec22e1311587aab8bb474362c8c35d3eb8b20a8caa"
        );
        let mut changed_native = native;
        changed_native[0] ^= 1;
        assert_ne!(
            binding,
            context
                .native_composition_binding(shared, changed_native, layout)
                .unwrap()
        );
        assert_ne!(
            binding,
            context
                .native_composition_binding(
                    BlsDorySharedOpeningBindingV5(native),
                    shared.into_bytes(),
                    layout,
                )
                .unwrap()
        );
        let mut changed_shared = shared.into_bytes();
        changed_shared[0] ^= 1;
        assert_ne!(
            binding,
            context
                .native_composition_binding(
                    BlsDorySharedOpeningBindingV5(changed_shared),
                    native,
                    layout,
                )
                .unwrap()
        );
        let mut changed_context = context;
        changed_context.setup_identity = Digest32::new([0x34; 32]);
        assert_ne!(
            binding,
            changed_context
                .native_composition_binding(shared, native, layout)
                .unwrap()
        );
        assert_eq!(
            context.native_composition_binding(
                shared,
                native,
                BlsDoryAggregateLayout::new(2, 4).unwrap(),
            ),
            Err(BlsDorySharedLayoutError::InvalidProofShape)
        );
        assert_eq!(
            context.native_composition_binding(shared, [0; 32], layout),
            Err(BlsDorySharedLayoutError::OpeningClaims)
        );
    }

    #[test]
    fn shared_native_composition_binding_is_ordered_and_context_bound() {
        let setup = deterministic_bls_dory_setup(6).unwrap();
        let layout = BlsDoryAggregateLayout::new(3, 3).unwrap();
        let shared = [0x11; 32];
        let native = [0x22; 32];
        let binding = shared_native_composed_opening_binding(shared, native, layout, &setup);

        assert_ne!(binding, [0; 32]);
        assert_eq!(
            binding,
            shared_native_composed_opening_binding(shared, native, layout, &setup)
        );
        assert_ne!(
            binding,
            shared_native_composed_opening_binding(native, shared, layout, &setup)
        );
        assert_ne!(
            binding,
            shared_native_composed_opening_binding(
                shared,
                native,
                BlsDoryAggregateLayout::new(2, 4).unwrap(),
                &setup,
            )
        );

        let other_setup = deterministic_bls_dory_setup(7).unwrap();
        assert_ne!(
            binding,
            shared_native_composed_opening_binding(shared, native, layout, &other_setup)
        );
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    #[ignore = "real 21-variable shared/native aggregate; run explicitly in --release"]
    fn shared_native_aggregate_authenticates_exact_128_plus_6_claims_end_to_end() {
        const PADDED_VARIABLES: usize = 21;
        const FINAL_ACTIVATION_BYTES: usize = 32;

        let total_started = std::time::Instant::now();
        let fixture_started = std::time::Instant::now();
        let fixture = linked_fixture_shape(3, 128, 16, 2);
        let fixture_millis = fixture_started.elapsed().as_millis();
        let matrix_statements = vec![fixture.matrix_statement; fixture.matrices.len()];
        let transition_statements = fixture
            .transitions
            .iter()
            .map(|transition| transition.statement)
            .collect::<Vec<_>>();
        let masks = fixture
            .transitions
            .iter()
            .map(|transition| &transition.mask)
            .collect::<Vec<_>>();
        let transition_inputs = fixture
            .transitions
            .iter()
            .map(|transition| BlsDoryTransitionProverInput {
                statement: transition.statement,
                mask_polynomial: &transition.mask,
                witness: &transition.witness,
            })
            .collect::<Vec<_>>();

        let setup_started = std::time::Instant::now();
        let setup = deterministic_bls_dory_setup(PADDED_VARIABLES).unwrap();
        let setup_millis = setup_started.elapsed().as_millis();
        let layout = BlsDoryAggregateLayout::new(10, 11).unwrap();
        let (model, fixed_model) =
            fixed_model_fixture_at_variables(&fixture, &setup, PADDED_VARIABLES);
        let scratch = ScratchDirectory::create();
        let observer = ScratchPeakObserver::start(scratch.0.clone());
        let precommitted_weights = fixture
            .matrices
            .iter()
            .map(|matrix| {
                commit_fixed_table_with_optional_scratch(
                    &matrix.weights,
                    PADDED_VARIABLES,
                    &setup,
                    Some(&scratch.0),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let precommitted_inputs = fixture
            .matrices
            .iter()
            .zip(&precommitted_weights)
            .map(|(matrix, weight)| BlsDoryPrecommittedMatrixProverInput {
                statement: fixture.matrix_statement,
                activations: &matrix.activations,
                weight,
                accumulators: &matrix.accumulators,
            })
            .collect::<Vec<_>>();

        let shared_started = std::time::Instant::now();
        let shared =
            prepare_bls_dory_shared_layout_with_precommitted_weights_at_variables_with_scratch(
                b"shared-native-134",
                &model,
                &fixed_model,
                &precommitted_inputs,
                &transition_inputs,
                fixture.wiring_statement,
                &fixture.initial,
                &fixture.inputs,
                &fixture.outputs,
                PADDED_VARIABLES,
                &setup,
                &scratch.0,
            )
            .unwrap();
        drop(precommitted_inputs);
        drop(precommitted_weights);
        let shared_millis = shared_started.elapsed().as_millis();
        assert_eq!(
            shared.expected_claims.len(),
            BLS_DORY_SHARED_PRODUCTION_CLAIMS
        );

        let pending_cell_point = shared.pending_final_output().cell_point().to_vec();
        let pending_signed_evaluation = shared.pending_final_output().signed_evaluation();
        let pending_transcript_binding = shared.pending_final_output().transcript_binding();
        let shared_boundary_claim = shared.expected_claims.last().unwrap().clone();
        let final_signed = &fixture.outputs[fixture.outputs.len() - FINAL_ACTIVATION_BYTES..];
        let final_activation = final_signed
            .iter()
            .map(|value| u8::try_from(value + 125).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(final_activation.len(), FINAL_ACTIVATION_BYTES);
        let challenge_digest = *blake3::hash(b"CommonFoundry/shared-native-134/e2e").as_bytes();
        let activation_digest =
            crate::forgematrix_v2::output_digest(challenge_digest, &final_activation);
        let bridge = BlsDoryOutputBridgeStatement::from_test_parts(
            challenge_digest,
            activation_digest,
            &final_activation,
            pending_transcript_binding,
            pending_cell_point.clone(),
        )
        .unwrap();
        assert_eq!(
            bridge.raw_byte_evaluation(),
            pending_signed_evaluation + BlsDoryFr::from_u64(125)
        );

        let native = prepare_native_blake3_test_opening_at_layout(
            &final_activation,
            &bridge,
            layout,
            &setup,
            &scratch.0,
        )
        .unwrap();
        let native_telemetry = native.telemetry;
        let encoded_native_proof = native.encoded_native_proof.clone();
        let trusted_preprocessing_commitment = native.trusted_preprocessing_commitment;
        let original_native_statement = native.opening_statement.clone();
        let replay_native = |encoded: &[u8], preprocessing_commitment: BlsDoryGt| {
            verify_encoded_native_blake3_test_opening_statement_at_layout(
                &bridge,
                encoded,
                preprocessing_commitment,
                layout,
                &setup,
            )
        };
        let native_statement =
            replay_native(&encoded_native_proof, trusted_preprocessing_commitment).unwrap();
        assert_eq!(native_statement, original_native_statement);
        let native_binding = native_statement.opening_binding();
        let native_claims = native_statement.claims();
        native_statement.validate_claims(&native_claims).unwrap();
        assert_eq!(
            native_claims.len(),
            BLS_DORY_SHARED_NATIVE_COMPOSITION_CLAIMS
        );

        let aggregate_started = std::time::Instant::now();
        let proof = prove_prepared_bls_dory_shared_layout_with_composition(
            shared,
            native.opening_set,
            native_binding,
            &setup,
            &scratch.0,
        )
        .unwrap();
        let aggregate_millis = aggregate_started.elapsed().as_millis();
        let peak_scratch_bytes = observer.finish();
        assert_eq!(proof.opening_proof.len(), 46_159);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
        assert_eq!(observed_directory_bytes(&scratch.0), 0);

        let encoded = proof
            .encode(
                &matrix_statements,
                &transition_statements,
                fixture.wiring_statement,
            )
            .unwrap();
        let encoded_candidate = BlsDoryV3CandidatePayload {
            dory_proof: encoded.clone(),
            native_blake3_proof: encoded_native_proof.clone(),
        }
        .encode()
        .unwrap();
        let candidate = BlsDoryV3CandidatePayload::decode(&encoded_candidate).unwrap();
        assert_eq!(candidate.dory_proof, encoded);
        assert_eq!(candidate.native_blake3_proof, encoded_native_proof);
        assert!(
            BlsDoryV3CandidatePayload::decode(&encoded_candidate[..encoded_candidate.len() - 1])
                .is_err()
        );
        let mut trailing_candidate = encoded_candidate.clone();
        trailing_candidate.push(0);
        assert!(BlsDoryV3CandidatePayload::decode(&trailing_candidate).is_err());
        let mut changed_native_candidate = encoded_candidate.clone();
        let changed_native_index = changed_native_candidate.len() - 1;
        changed_native_candidate[changed_native_index] ^= 1;
        let changed_native_candidate =
            BlsDoryV3CandidatePayload::decode(&changed_native_candidate).unwrap();
        assert!(
            replay_native(
                &changed_native_candidate.native_blake3_proof,
                trusted_preprocessing_commitment,
            )
            .is_err()
        );
        let decoded = BlsDorySharedLayoutProof::decode_with_variables(
            &candidate.dory_proof,
            &matrix_statements,
            &transition_statements,
            fixture.wiring_statement,
            PADDED_VARIABLES,
        )
        .unwrap();
        assert_eq!(decoded, proof);
        let proof = decoded;

        assert!(
            verify_bls_dory_shared_layout_with_final_output_at_variables(
                b"shared-native-134",
                &model,
                &fixed_model,
                &matrix_statements,
                &transition_statements,
                &masks,
                fixture.wiring_statement,
                &proof,
                PADDED_VARIABLES,
                &setup,
            )
            .is_err()
        );
        native_statement.validate_claims(&native_claims).unwrap();

        let prepare_verifier = |candidate: &BlsDorySharedLayoutProof| {
            prepare_bls_dory_shared_layout_verifier_state_for_test(
                b"shared-native-134",
                &model,
                &fixed_model,
                &matrix_statements,
                &transition_statements,
                &masks,
                fixture.wiring_statement,
                candidate,
                PADDED_VARIABLES,
                &setup,
            )
        };
        let verifier_started = std::time::Instant::now();
        let verifier = prepare_verifier(&proof).unwrap();
        assert_eq!(verifier.claims.len(), BLS_DORY_SHARED_PRODUCTION_CLAIMS);
        let verified = verify_prepared_bls_dory_shared_layout_with_test_native_proof(
            verifier,
            challenge_digest,
            activation_digest,
            FINAL_ACTIVATION_BYTES,
            &candidate.native_blake3_proof,
            trusted_preprocessing_commitment,
            &proof.opening_proof,
            &setup,
        )
        .unwrap();
        let verifier_millis = verifier_started.elapsed().as_millis();
        assert_eq!(verified.cell_point(), pending_cell_point);
        assert_eq!(verified.signed_evaluation(), pending_signed_evaluation);
        assert_eq!(verified.transcript_binding(), pending_transcript_binding);

        let mut changed_native_proof = encoded_native_proof.clone();
        let changed_native_index = changed_native_proof.len() - 1;
        changed_native_proof[changed_native_index] ^= 1;
        assert!(replay_native(&changed_native_proof, trusted_preprocessing_commitment,).is_err());
        assert!(
            replay_native(
                &encoded_native_proof[..encoded_native_proof.len() - 1],
                trusted_preprocessing_commitment,
            )
            .is_err()
        );
        assert!(replay_native(&encoded_native_proof, native_claims[0].commitment,).is_err());

        let mut wrong_route = native_claims.clone();
        wrong_route[0].commitment = wrong_route[2].commitment;
        assert!(native_statement.validate_claims(&wrong_route).is_err());

        let mut wrong_evaluation = native_claims.clone();
        wrong_evaluation[0].evaluation = wrong_evaluation[0].evaluation + BlsDoryFr::one();
        assert!(native_statement.validate_claims(&wrong_evaluation).is_err());

        let mut shared_as_native = native_claims.clone();
        shared_as_native[0] = shared_boundary_claim;
        assert!(native_statement.validate_claims(&shared_as_native).is_err());

        let mut changed_final_evaluation = proof.clone();
        changed_final_evaluation.final_output_evaluation =
            changed_final_evaluation.final_output_evaluation + BlsDoryFr::one();
        assert!(
            verify_prepared_bls_dory_shared_layout_with_test_native_proof(
                prepare_verifier(&changed_final_evaluation).unwrap(),
                challenge_digest,
                activation_digest,
                FINAL_ACTIVATION_BYTES,
                &encoded_native_proof,
                trusted_preprocessing_commitment,
                &changed_final_evaluation.opening_proof,
                &setup,
            )
            .is_err()
        );

        let mut changed_challenge = challenge_digest;
        changed_challenge[0] ^= 1;
        assert!(
            verify_prepared_bls_dory_shared_layout_with_test_native_proof(
                prepare_verifier(&proof).unwrap(),
                changed_challenge,
                activation_digest,
                FINAL_ACTIVATION_BYTES,
                &encoded_native_proof,
                trusted_preprocessing_commitment,
                &proof.opening_proof,
                &setup,
            )
            .is_err()
        );

        let mut changed_opening_proof = proof.opening_proof.clone();
        let changed_index = changed_opening_proof.len() / 2;
        changed_opening_proof[changed_index] ^= 1;
        assert!(
            verify_prepared_bls_dory_shared_layout_with_test_native_proof(
                prepare_verifier(&proof).unwrap(),
                challenge_digest,
                activation_digest,
                FINAL_ACTIVATION_BYTES,
                &encoded_native_proof,
                trusted_preprocessing_commitment,
                &changed_opening_proof,
                &setup,
            )
            .is_err()
        );

        eprintln!(
            "CMFD_SHARED_NATIVE_E2E {{\"fixture_ms\":{fixture_millis},\"setup_ms\":{setup_millis},\"shared_prepare_ms\":{shared_millis},\"native_fixture_ms\":{},\"native_source_ms\":{},\"native_sumcheck_ms\":{},\"native_finalize_ms\":{},\"aggregate_ms\":{aggregate_millis},\"verify_ms\":{verifier_millis},\"total_ms\":{},\"claims\":134,\"opening_proof_bytes\":{},\"outer_proof_bytes\":{},\"native_proof_bytes\":{},\"peak_scratch_bytes\":{peak_scratch_bytes},\"scratch_entries\":{},\"scratch_bytes\":{}}}",
            native_telemetry.fixture_millis,
            native_telemetry.source_millis,
            native_telemetry.sumcheck_millis,
            native_telemetry.finalize_millis,
            total_started.elapsed().as_millis(),
            proof.opening_proof.len(),
            encoded.len(),
            encoded_native_proof.len(),
            std::fs::read_dir(&scratch.0).unwrap().count(),
            observed_directory_bytes(&scratch.0),
        );
    }
}
