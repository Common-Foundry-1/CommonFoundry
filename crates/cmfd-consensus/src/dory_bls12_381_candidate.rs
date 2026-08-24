//! Non-consensus verifier boundary for the production-shaped composed BLS/Dory proof.
//!
//! The composed research path verifies both the shared ForgeMatrix arithmetic
//! layout and the native final-output BLAKE3 argument in one aggregate. This
//! module intentionally cannot produce [`crate::PreverifiedBlockProof`]: the
//! production prover and preprocessing registry are not complete, the exact
//! n=33 run has not completed, and the required review and audit gates remain
//! open.

use std::sync::Arc;
#[cfg(feature = "whir-prototype")]
use std::{io::Read, path::Path, sync::atomic::AtomicBool};

use thiserror::Error;

use crate::{
    BlockChallenge, ForgeMatrixV2Descriptor, ForgeMatrixV3CandidateProof, ModelBankError,
    ModelBankManifest, ModelPcsIdentity, POW_TYPE_V3_CANDIDATE, PRODUCTION_V2_BANKS,
    PRODUCTION_V2_BATCH, PRODUCTION_V2_DIMENSION, PRODUCTION_V2_LAYERS,
    PRODUCTION_V2_LAYERS_PER_BANK, StructuredMaskPolynomial, StructuredMatrixStatement,
    StructuredTransitionError, StructuredTransitionStatement, StructuredWiringStatement,
    dory_bls12_381_layout::{
        BLS_DORY_SHARED_PRODUCTION_VARIABLES, BlsDoryFixedModelIdentity, BlsDorySharedLayoutError,
        BlsDorySharedLayoutProof, VerifiedBlsDoryFinalOutputOpening,
        verify_bls_dory_shared_layout_with_final_output_at_variables,
    },
    dory_bls12_381_model_commitment::{
        BlsDoryModelCommitmentRecord, BlsDoryModelCommitmentRecordError,
    },
    dory_bls12_381_prototype::DeterministicBlsDorySetup,
    forgematrix_v2::{
        FORGEMATRIX_V2_ALGORITHM_VERSION, FORGEMATRIX_V2_PROOF_VERSION, challenge_digest,
        work_digest_from_roots,
    },
    structured_proof::StructuredForgeMatrixResearchShape,
    wire::MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES,
};

#[cfg(feature = "whir-prototype")]
use crate::{
    StructuredTransitionWitness,
    dory_bls12_381_aggregate::BlsDoryAggregateError,
    dory_bls12_381_blake3::{
        BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES, PreparedBlsDoryNativeBlake3Opening,
        prepare_production_native_blake3_opening, projected_bls_dory_blake3_production_resources,
    },
    dory_bls12_381_execution_artifact::{
        BlsDoryExecutionAccumulatorArtifact, BlsDoryExecutionAccumulatorArtifactContext,
        BlsDoryExecutionAccumulatorArtifactError,
    },
    dory_bls12_381_execution_provider::{
        BlsDoryWinningNonceClaim, BlsDoryWinningNonceReplayError,
        VerifiedBlsDoryWinningNonceExecution,
        replay_winning_nonce_from_verified_bank as replay_verified_winning_nonce,
    },
    dory_bls12_381_layout::{
        BlsDoryPrecommittedMatrixProverInput, BlsDoryPreparedFixedModel,
        BlsDorySharedLayoutV5Context, BlsDorySharedLayoutV5Proof, BlsDoryTransitionProverInput,
        PreparedBlsDorySharedLayoutProverState,
        extract_bls_dory_final_activation_from_execution_artifact,
        prepare_bls_dory_shared_layout_from_execution_artifact_with_scratch,
        prepare_bls_dory_shared_layout_v5_verifier_state,
        prepare_bls_dory_shared_layout_verifier_state,
        prepare_bls_dory_shared_layout_with_precommitted_weights_at_variables_with_scratch,
        projected_shared_production_scratch_bytes,
        prove_prepared_bls_dory_shared_layout_with_composition,
        verify_prepared_bls_dory_shared_layout_v5_with_native_proof,
        verify_prepared_bls_dory_shared_layout_with_native_proof,
    },
    dory_bls12_381_logup::{
        projected_production_range_logup_early_lineage_peak_bytes,
        projected_production_transition_range_source_bytes,
    },
    dory_bls12_381_output_bridge::{BlsDoryOutputBridgeError, BlsDoryOutputBridgeStatement},
    dory_v3_model_record::{
        BankAuthenticatedDoryV3ModelCommitmentRecordV2, DoryV3ModelCommitmentRecordError,
    },
    dory_v3_suite::{DORY_V3_ALGORITHM_VERSION, DORY_V3_PROOF_VERSION},
    dory_v3_transcript::{DoryV3TranscriptContext, DoryV3TranscriptError},
    forgematrix_v2::output_digest,
};

pub(crate) const ALGEBRAIC_BINDING_VERSION: u16 = 1;
pub(crate) const ALGEBRAIC_BINDING_DOMAIN: &str =
    "CommonFoundry/ForgeMatrix/V3/BlsDoryAlgebraicBinding/v1";
pub(crate) const CANDIDATE_PAYLOAD_MAGIC: [u8; 8] = *b"CFV3CP02";
pub(crate) const CANDIDATE_PAYLOAD_VERSION: u16 = 2;
pub(crate) const CANDIDATE_PAYLOAD_HEADER_BYTES: usize = 18;
pub(crate) const CANDIDATE_PAYLOAD_FIELDS: &str = "magic[8],version_u16le,dory_length_u32le,native_blake3_length_u32le,dory_bytes,native_blake3_bytes; exact EOF";

/// Production-shaped verifier for only the algebraic portion of a V3 candidate.
///
/// Construction requires an authenticated fixed-model commitment record and
/// exact n=33 setup. The final hash/table link remains deliberately outside
/// this type so it cannot be mistaken for a consensus verifier.
pub struct BlsDoryV3AlgebraicVerifier {
    network_id: [u8; 32],
    manifest: ModelBankManifest,
    trusted_model: ModelPcsIdentity,
    fixed_model: BlsDoryFixedModelIdentity,
    record_digest: [u8; 32],
    setup: Arc<DeterministicBlsDorySetup>,
}

struct ValidatedBlsDoryV3CandidateStatement {
    binding: [u8; 32],
    shape: StructuredForgeMatrixResearchShape,
    transition_statements: Vec<StructuredTransitionStatement>,
    masks: Vec<StructuredMaskPolynomial>,
}

#[cfg(feature = "whir-prototype")]
struct ValidatedBlsDoryV3LayoutV5CandidateStatement {
    binding: [u8; 32],
    challenge_digest: [u8; 32],
    shape: StructuredForgeMatrixResearchShape,
    transition_statements: Vec<StructuredTransitionStatement>,
    masks: Vec<StructuredMaskPolynomial>,
}

#[cfg(feature = "whir-prototype")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BlsDoryV3CandidateScratchProjection {
    conservative_future_retained_source_bytes: u64,
    shared_construction_peak_bytes: u64,
    shared_aggregate_peak_bytes: u64,
    native_execution_peak_bytes: u64,
    native_adjacency_peak_bytes: u64,
    native_aggregate_peak_bytes: u64,
    required_free_bytes: u64,
}

/// Opaque evidence that one exact candidate passed only the Dory algebraic checks.
///
/// This value is intentionally unrelated to the chain-admission capability.
/// Its binding is exposed only for diagnostics and later hash-bridge composition.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBlsDoryV3AlgebraicCandidate {
    binding: [u8; 32],
    proof_digest: [u8; 32],
    final_output: VerifiedBlsDoryFinalOutputOpening,
}

/// Canonical candidate envelope carrying the shared proof and native BLAKE3 frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsDoryV3CandidatePayload {
    pub dory_proof: Vec<u8>,
    pub native_blake3_proof: Vec<u8>,
}

/// One production matrix witness. Statements, weights, masks, and geometry are
/// derived from the pinned candidate configuration rather than supplied here.
#[cfg(feature = "whir-prototype")]
#[derive(Clone, Copy, Debug)]
pub struct BlsDoryV3CandidateMatrixWitness<'a> {
    pub activations: &'a [i64],
    pub accumulators: &'a [i64],
}

/// Canonically ordered production execution witness consumed by the research
/// candidate constructor. The first transition is initialization; the next
/// three are the model banks. The final activation is derived from the tail of
/// `wiring_outputs` and is never accepted separately.
#[cfg(feature = "whir-prototype")]
#[derive(Debug)]
pub struct BlsDoryV3CandidateWitness<'a> {
    pub matrices: &'a [BlsDoryV3CandidateMatrixWitness<'a>],
    pub transitions: &'a [StructuredTransitionWitness],
    pub wiring_inputs: &'a [i64],
    pub wiring_outputs: &'a [i64],
}

/// Opaque evidence that the Dory execution proof and native BLAKE3 argument
/// verified in one aggregate against one candidate statement. Consensus activation stays
/// disabled until the remaining benchmark and review gates are complete.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBlsDoryV3Candidate {
    algebraic: VerifiedBlsDoryV3AlgebraicCandidate,
    native_blake3_proof_digest: [u8; 32],
}

/// Opaque evidence that the Record-V2-owned Layout V5 and Dory-V3 native
/// frames verified together. This dormant capability is deliberately distinct
/// from the legacy V4 candidate capability and cannot authorize consensus.
#[cfg(feature = "whir-prototype")]
#[must_use]
#[allow(dead_code)]
pub(crate) struct VerifiedBlsDoryV3LayoutV5Candidate {
    binding: [u8; 32],
    dory_proof_digest: [u8; 32],
    native_blake3_proof_digest: [u8; 32],
    final_output: VerifiedBlsDoryFinalOutputOpening,
}

impl VerifiedBlsDoryV3Candidate {
    pub const fn algebraic(&self) -> &VerifiedBlsDoryV3AlgebraicCandidate {
        &self.algebraic
    }

    pub const fn native_blake3_proof_digest(&self) -> [u8; 32] {
        self.native_blake3_proof_digest
    }
}

impl VerifiedBlsDoryV3AlgebraicCandidate {
    /// Exact public binding accepted by the algebraic verifier.
    pub const fn binding(&self) -> [u8; 32] {
        self.binding
    }

    /// Digest of the exact structured Dory bytes that were verified.
    pub const fn proof_digest(&self) -> [u8; 32] {
        self.proof_digest
    }

    /// Dory-authenticated final output opening for the still-required BLAKE3
    /// cross-field bridge.
    pub const fn final_output(&self) -> &VerifiedBlsDoryFinalOutputOpening {
        &self.final_output
    }
}

#[derive(Debug, Error)]
pub enum BlsDoryV3CandidateError {
    #[error("the V3 algebraic verifier requires a nonzero network identity")]
    NetworkIdentity,
    #[error("the block belongs to a different network")]
    WrongNetwork,
    #[error("the commitment record does not describe the exact production geometry")]
    ProductionGeometry,
    #[error("the fixed-model commitment record is invalid: {0}")]
    ModelRecord(#[from] BlsDoryModelCommitmentRecordError),
    #[error("the model manifest or PCS identity is invalid: {0}")]
    Model(#[from] ModelBankError),
    #[error("candidate algorithm version mismatch")]
    AlgorithmVersion,
    #[error("candidate proof version mismatch")]
    ProofVersion,
    #[error("candidate model-manifest digest mismatch")]
    ModelManifestDigest,
    #[error("candidate challenge digest mismatch")]
    ChallengeDigest,
    #[error("candidate work digest mismatch")]
    WorkDigest,
    #[error("candidate work digest does not meet the block target")]
    HighHash,
    #[error("candidate structured proof is empty or exceeds its wire allowance")]
    ProofSize,
    #[error("candidate proof envelope is malformed")]
    Payload,
    #[error("candidate mask derivation failed: {0}")]
    Mask(#[from] StructuredTransitionError),
    #[error("candidate Dory proof failed: {0}")]
    Dory(#[from] BlsDorySharedLayoutError),
    #[cfg(feature = "whir-prototype")]
    #[error("candidate native BLAKE3 proof failed: {0}")]
    NativeBlake3(#[from] BlsDoryAggregateError),
    #[cfg(feature = "whir-prototype")]
    #[error("candidate final-output bridge failed: {0}")]
    OutputBridge(#[from] BlsDoryOutputBridgeError),
    #[cfg(feature = "whir-prototype")]
    #[error("candidate execution witness does not have the exact production shape")]
    WitnessShape,
    #[cfg(feature = "whir-prototype")]
    #[error("candidate prover configuration is not valid for the production shape")]
    ProverConfiguration,
    #[cfg(feature = "whir-prototype")]
    #[error("candidate scratch-space projection is invalid")]
    ScratchProjection,
    #[cfg(feature = "whir-prototype")]
    #[error("candidate scratch-space query failed: {0}")]
    ScratchSpaceQuery(#[source] std::io::Error),
    #[cfg(feature = "whir-prototype")]
    #[error("insufficient candidate scratch space: need {required} bytes, have {available} bytes")]
    InsufficientScratch { required: u64, available: u64 },
    #[cfg(feature = "whir-prototype")]
    #[error("candidate final activation is outside the canonical centered-byte range")]
    FinalActivation,
    #[cfg(feature = "whir-prototype")]
    #[error("candidate execution-accumulator artifact context is invalid: {0}")]
    ExecutionArtifact(#[from] BlsDoryExecutionAccumulatorArtifactError),
    #[cfg(feature = "whir-prototype")]
    #[error("verified winning-nonce execution does not match this candidate statement")]
    VerifiedExecution,
    #[cfg(feature = "whir-prototype")]
    #[error("candidate Record V2 authority is invalid: {0}")]
    DoryV3Record(#[from] DoryV3ModelCommitmentRecordError),
    #[cfg(feature = "whir-prototype")]
    #[error("candidate Dory V3 transcript is invalid: {0}")]
    DoryV3Transcript(#[from] DoryV3TranscriptError),
}

impl BlsDoryV3CandidatePayload {
    pub fn encode(&self) -> Result<Vec<u8>, BlsDoryV3CandidateError> {
        if self.dory_proof.is_empty() || self.native_blake3_proof.is_empty() {
            return Err(BlsDoryV3CandidateError::Payload);
        }
        let dory_len =
            u32::try_from(self.dory_proof.len()).map_err(|_| BlsDoryV3CandidateError::Payload)?;
        let blake3_len = u32::try_from(self.native_blake3_proof.len())
            .map_err(|_| BlsDoryV3CandidateError::Payload)?;
        let total = CANDIDATE_PAYLOAD_HEADER_BYTES
            .checked_add(self.dory_proof.len())
            .and_then(|total| total.checked_add(self.native_blake3_proof.len()))
            .ok_or(BlsDoryV3CandidateError::Payload)?;
        if total > MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES {
            return Err(BlsDoryV3CandidateError::ProofSize);
        }
        let mut encoded = Vec::with_capacity(total);
        encoded.extend_from_slice(&CANDIDATE_PAYLOAD_MAGIC);
        encoded.extend_from_slice(&CANDIDATE_PAYLOAD_VERSION.to_le_bytes());
        encoded.extend_from_slice(&dory_len.to_le_bytes());
        encoded.extend_from_slice(&blake3_len.to_le_bytes());
        encoded.extend_from_slice(&self.dory_proof);
        encoded.extend_from_slice(&self.native_blake3_proof);
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, BlsDoryV3CandidateError> {
        if encoded.len() < CANDIDATE_PAYLOAD_HEADER_BYTES
            || encoded.len() > MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES
            || encoded[..8] != CANDIDATE_PAYLOAD_MAGIC
        {
            return Err(BlsDoryV3CandidateError::Payload);
        }
        let version = u16::from_le_bytes(
            encoded[8..10]
                .try_into()
                .map_err(|_| BlsDoryV3CandidateError::Payload)?,
        );
        let dory_len = u32::from_le_bytes(
            encoded[10..14]
                .try_into()
                .map_err(|_| BlsDoryV3CandidateError::Payload)?,
        ) as usize;
        let blake3_len = u32::from_le_bytes(
            encoded[14..18]
                .try_into()
                .map_err(|_| BlsDoryV3CandidateError::Payload)?,
        ) as usize;
        let dory_end = CANDIDATE_PAYLOAD_HEADER_BYTES
            .checked_add(dory_len)
            .ok_or(BlsDoryV3CandidateError::Payload)?;
        let end = dory_end
            .checked_add(blake3_len)
            .ok_or(BlsDoryV3CandidateError::Payload)?;
        if version != CANDIDATE_PAYLOAD_VERSION
            || dory_len == 0
            || blake3_len == 0
            || end != encoded.len()
        {
            return Err(BlsDoryV3CandidateError::Payload);
        }
        Ok(Self {
            dory_proof: encoded[CANDIDATE_PAYLOAD_HEADER_BYTES..dory_end].to_vec(),
            native_blake3_proof: encoded[dory_end..end].to_vec(),
        })
    }
}

impl BlsDoryV3AlgebraicVerifier {
    /// Pin one authenticated production model and its exact deterministic setup.
    pub fn new(
        network_id: [u8; 32],
        record: &BlsDoryModelCommitmentRecord,
        setup: Arc<DeterministicBlsDorySetup>,
    ) -> Result<Self, BlsDoryV3CandidateError> {
        if network_id == [0; 32] {
            return Err(BlsDoryV3CandidateError::NetworkIdentity);
        }
        record.validate(&setup)?;
        validate_production_record(record, &setup)?;
        Ok(Self {
            network_id,
            manifest: record.manifest,
            trusted_model: record.model_pcs_identity.clone(),
            fixed_model: record.fixed_identity()?,
            record_digest: record.canonical_digest()?,
            setup,
        })
    }

    /// Derive the only execution-artifact context accepted for this pinned
    /// verifier and candidate. Callers supply no network, model, setup, or
    /// challenge identities.
    #[cfg(feature = "whir-prototype")]
    pub(crate) fn execution_artifact_context(
        &self,
        block: &BlockChallenge,
        nonce: u64,
    ) -> Result<BlsDoryExecutionAccumulatorArtifactContext, BlsDoryV3CandidateError> {
        if block.network_id != self.network_id {
            return Err(BlsDoryV3CandidateError::WrongNetwork);
        }
        let challenge = challenge_digest(&self.descriptor(), block, nonce)
            .map_err(|_| BlsDoryV3CandidateError::ChallengeDigest)?;
        Ok(BlsDoryExecutionAccumulatorArtifactContext::production(
            self.network_id,
            self.record_digest,
            self.setup.identity(),
            challenge,
        )?)
    }

    /// Recompute an accelerator-proposed winning nonce on the CPU while the
    /// canonical model bank is authenticated on the same reader. GPU output is
    /// only a cheap candidate hint; the returned execution capability exists
    /// only after every accumulator, final activation, and public digest has
    /// been reconstructed from the verifier's pinned model.
    #[cfg(feature = "whir-prototype")]
    pub fn replay_winning_nonce_from_verified_bank<R: Read>(
        &self,
        block: &BlockChallenge,
        claim: BlsDoryWinningNonceClaim,
        model_bank: R,
        scratch_directory: &Path,
        cancel: &AtomicBool,
    ) -> Result<VerifiedBlsDoryWinningNonceExecution, BlsDoryWinningNonceReplayError> {
        if block.network_id != self.network_id {
            return Err(BlsDoryWinningNonceReplayError::WrongNetwork);
        }
        let context = self
            .execution_artifact_context(block, claim.nonce)
            .map_err(|_| BlsDoryWinningNonceReplayError::CandidateContext)?;
        replay_verified_winning_nonce(
            context,
            &self.manifest,
            &self.trusted_model,
            block.target,
            claim,
            model_bank,
            scratch_directory,
            cancel,
        )
    }

    /// Consume one CPU-replayed execution capability and construct the exact
    /// production candidate it authenticates. A capability cannot be reused
    /// for a different block, nonce, verifier, model, or setup because the
    /// execution artifact context is checked before proving and then consumed.
    #[cfg(feature = "whir-prototype")]
    pub fn prove_candidate_from_verified_execution(
        &self,
        block: &BlockChallenge,
        prepared_model: &BlsDoryPreparedFixedModel,
        execution: VerifiedBlsDoryWinningNonceExecution,
        scratch_directory: &Path,
        maximum_native_block_rows: usize,
    ) -> Result<ForgeMatrixV3CandidateProof, BlsDoryV3CandidateError> {
        let (nonce, final_activation_digest, work_digest, artifact) = execution.into_parts();
        let expected_context = self.execution_artifact_context(block, nonce)?;
        if artifact.context() != expected_context {
            return Err(BlsDoryV3CandidateError::VerifiedExecution);
        }
        let proof = self.prove_candidate_from_execution_artifact(
            block,
            nonce,
            prepared_model,
            artifact,
            scratch_directory,
            maximum_native_block_rows,
        )?;
        if proof.final_activation_digest != final_activation_digest
            || proof.work_digest != work_digest
        {
            return Err(BlsDoryV3CandidateError::VerifiedExecution);
        }
        Ok(proof)
    }

    /// Construct and self-verify one exact production-shaped research
    /// candidate. All public fields, statements, masks, and fixed commitments
    /// are derived from this verifier's pinned configuration. This method does
    /// not create a chain-admission capability or enable production consensus.
    #[cfg(feature = "whir-prototype")]
    #[allow(clippy::too_many_arguments)]
    pub fn prove_candidate(
        &self,
        block: &BlockChallenge,
        nonce: u64,
        prepared_model: &BlsDoryPreparedFixedModel,
        witness: BlsDoryV3CandidateWitness<'_>,
        scratch_directory: &Path,
        maximum_native_block_rows: usize,
    ) -> Result<ForgeMatrixV3CandidateProof, BlsDoryV3CandidateError> {
        self.validate_prover_configuration(
            block,
            prepared_model,
            scratch_directory,
            maximum_native_block_rows,
        )?;

        let shape = StructuredForgeMatrixResearchShape::production_candidate();
        shape
            .validate_verifier_shape()
            .map_err(|_| BlsDoryV3CandidateError::ProductionGeometry)?;
        validate_production_witness_shape(&shape, &witness)?;
        let final_activation = production_final_activation(witness.wiring_outputs)?;
        let manifest_digest = self.manifest.digest()?;
        let challenge_digest = self
            .execution_artifact_context(block, nonce)?
            .challenge_identity();
        let final_activation_digest = output_digest(challenge_digest, &final_activation);
        let work_digest = work_digest_from_roots(
            challenge_digest,
            self.manifest.raw_blake3_root,
            self.manifest.pcs_commitment_root,
            final_activation_digest,
        );
        if work_digest > block.target {
            return Err(BlsDoryV3CandidateError::HighHash);
        }

        preflight_candidate_scratch(scratch_directory)?;

        let proof = ForgeMatrixV3CandidateProof {
            algorithm_version: FORGEMATRIX_V2_ALGORITHM_VERSION,
            proof_version: FORGEMATRIX_V2_PROOF_VERSION,
            nonce,
            model_manifest_digest: manifest_digest,
            challenge_digest,
            final_activation_digest,
            work_digest,
            structured_proof: Vec::new(),
        };
        let validated = self.validate_candidate_public_statement(block, &proof)?;

        let matrix_inputs = validated
            .shape
            .matrix_statements
            .iter()
            .zip(witness.matrices.iter())
            .zip(prepared_model.weight_banks())
            .map(
                |((statement, matrix), weight)| BlsDoryPrecommittedMatrixProverInput {
                    statement: *statement,
                    activations: matrix.activations,
                    weight,
                    accumulators: matrix.accumulators,
                },
            )
            .collect::<Vec<_>>();
        let transition_inputs = validated
            .transition_statements
            .iter()
            .zip(&validated.masks)
            .zip(witness.transitions.iter())
            .map(
                |((statement, mask_polynomial), transition)| BlsDoryTransitionProverInput {
                    statement: *statement,
                    mask_polynomial,
                    witness: transition,
                },
            )
            .collect::<Vec<_>>();
        let shared =
            prepare_bls_dory_shared_layout_with_precommitted_weights_at_variables_with_scratch(
                &validated.binding,
                &self.trusted_model,
                &self.fixed_model,
                &matrix_inputs,
                &transition_inputs,
                validated.shape.wiring_statement,
                &witness.transitions[0].activations,
                witness.wiring_inputs,
                witness.wiring_outputs,
                BLS_DORY_SHARED_PRODUCTION_VARIABLES,
                &self.setup,
                scratch_directory,
            )?;
        self.finish_prepared_candidate(
            block,
            proof,
            &validated,
            shared,
            &final_activation,
            scratch_directory,
            maximum_native_block_rows,
        )
    }

    /// Construct and self-verify one exact production-shaped research
    /// candidate directly from an authenticated execution artifact. The
    /// artifact is consumed so its large accumulator file is deleted before
    /// native BLAKE3 proving begins. Callers cannot supply any artifact
    /// identity, public statement, mask, or dense witness table.
    #[cfg(feature = "whir-prototype")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prove_candidate_from_execution_artifact(
        &self,
        block: &BlockChallenge,
        nonce: u64,
        prepared_model: &BlsDoryPreparedFixedModel,
        mut artifact: BlsDoryExecutionAccumulatorArtifact,
        scratch_directory: &Path,
        maximum_native_block_rows: usize,
    ) -> Result<ForgeMatrixV3CandidateProof, BlsDoryV3CandidateError> {
        self.validate_prover_configuration(
            block,
            prepared_model,
            scratch_directory,
            maximum_native_block_rows,
        )?;

        let shape = StructuredForgeMatrixResearchShape::production_candidate();
        shape
            .validate_verifier_shape()
            .map_err(|_| BlsDoryV3CandidateError::ProductionGeometry)?;
        let expected_context = self.execution_artifact_context(block, nonce)?;
        let challenge_digest = expected_context.challenge_identity();
        let mut transition_statements = Vec::with_capacity(PRODUCTION_V2_BANKS as usize + 1);
        transition_statements.push(shape.initialization_statement);
        transition_statements.extend_from_slice(&shape.transition_statements);
        let masks = production_masks(challenge_digest, &shape)?;
        let final_activation = extract_bls_dory_final_activation_from_execution_artifact(
            *transition_statements
                .last()
                .ok_or(BlsDoryV3CandidateError::ProductionGeometry)?,
            masks
                .last()
                .ok_or(BlsDoryV3CandidateError::ProductionGeometry)?,
            &mut artifact,
            expected_context,
        )?;
        let manifest_digest = self.manifest.digest()?;
        let final_activation_digest = output_digest(challenge_digest, &final_activation);
        let work_digest = work_digest_from_roots(
            challenge_digest,
            self.manifest.raw_blake3_root,
            self.manifest.pcs_commitment_root,
            final_activation_digest,
        );
        if work_digest > block.target {
            return Err(BlsDoryV3CandidateError::HighHash);
        }

        preflight_candidate_scratch(scratch_directory)?;

        let proof = ForgeMatrixV3CandidateProof {
            algorithm_version: FORGEMATRIX_V2_ALGORITHM_VERSION,
            proof_version: FORGEMATRIX_V2_PROOF_VERSION,
            nonce,
            model_manifest_digest: manifest_digest,
            challenge_digest,
            final_activation_digest,
            work_digest,
            structured_proof: Vec::new(),
        };
        let validated = self.validate_candidate_public_statement(block, &proof)?;
        let mask_refs = validated.masks.iter().collect::<Vec<_>>();
        let shared = prepare_bls_dory_shared_layout_from_execution_artifact_with_scratch(
            &validated.binding,
            &self.trusted_model,
            prepared_model,
            &validated.shape.matrix_statements,
            &validated.transition_statements,
            &mask_refs,
            validated.shape.wiring_statement,
            &mut artifact,
            expected_context,
            BLS_DORY_SHARED_PRODUCTION_VARIABLES,
            &self.setup,
            scratch_directory,
        )?;

        // The prepared layout owns its opening capabilities. Releasing the
        // consumed execution artifact here removes its production-sized file
        // before the independent native BLAKE3 proof allocates scratch space.
        drop(artifact);
        self.finish_prepared_candidate(
            block,
            proof,
            &validated,
            shared,
            &final_activation,
            scratch_directory,
            maximum_native_block_rows,
        )
    }

    #[cfg(feature = "whir-prototype")]
    fn validate_prover_configuration(
        &self,
        block: &BlockChallenge,
        prepared_model: &BlsDoryPreparedFixedModel,
        scratch_directory: &Path,
        maximum_native_block_rows: usize,
    ) -> Result<(), BlsDoryV3CandidateError> {
        if block.network_id != self.network_id {
            return Err(BlsDoryV3CandidateError::WrongNetwork);
        }
        if maximum_native_block_rows == 0
            || !scratch_directory.is_absolute()
            || !scratch_directory.is_dir()
            || self.setup.max_log_n() != BLS_DORY_SHARED_PRODUCTION_VARIABLES
        {
            return Err(BlsDoryV3CandidateError::ProverConfiguration);
        }
        if prepared_model.identity() != &self.fixed_model
            || prepared_model.weight_banks().len() != PRODUCTION_V2_BANKS as usize
        {
            return Err(BlsDorySharedLayoutError::FixedModelIdentity.into());
        }
        Ok(())
    }

    #[cfg(feature = "whir-prototype")]
    #[allow(clippy::too_many_arguments)]
    fn finish_prepared_candidate(
        &self,
        block: &BlockChallenge,
        mut proof: ForgeMatrixV3CandidateProof,
        validated: &ValidatedBlsDoryV3CandidateStatement,
        shared: PreparedBlsDorySharedLayoutProverState,
        final_activation: &[u8],
        scratch_directory: &Path,
        maximum_native_block_rows: usize,
    ) -> Result<ForgeMatrixV3CandidateProof, BlsDoryV3CandidateError> {
        let bridge = BlsDoryOutputBridgeStatement::from_pending_dory(
            proof.challenge_digest,
            proof.final_activation_digest,
            final_activation.len(),
            shared.pending_final_output(),
        )?;
        bridge.validate_activation(final_activation)?;
        let PreparedBlsDoryNativeBlake3Opening {
            opening_statement,
            opening_set,
            encoded_native_proof,
        } = prepare_production_native_blake3_opening(
            final_activation,
            &bridge,
            &self.setup,
            scratch_directory,
            maximum_native_block_rows,
        )?;
        let native_opening_binding = opening_statement.opening_binding();
        let shared_proof = prove_prepared_bls_dory_shared_layout_with_composition(
            shared,
            opening_set,
            native_opening_binding,
            &self.setup,
            scratch_directory,
        )?;
        let dory_proof = shared_proof.encode(
            &validated.shape.matrix_statements,
            &validated.transition_statements,
            validated.shape.wiring_statement,
        )?;
        proof.structured_proof = BlsDoryV3CandidatePayload {
            dory_proof,
            native_blake3_proof: encoded_native_proof,
        }
        .encode()?;
        let _verified = self.verify_candidate(block, &proof)?;
        Ok(proof)
    }

    fn descriptor(&self) -> ForgeMatrixV2Descriptor {
        ForgeMatrixV2Descriptor {
            network_id: self.network_id,
            algorithm_version: FORGEMATRIX_V2_ALGORITHM_VERSION,
            proof_version: FORGEMATRIX_V2_PROOF_VERSION,
            banks: PRODUCTION_V2_BANKS,
            layers_per_bank: PRODUCTION_V2_LAYERS_PER_BANK,
            model: self.manifest,
        }
    }

    fn validate_candidate_public_statement(
        &self,
        block: &BlockChallenge,
        proof: &ForgeMatrixV3CandidateProof,
    ) -> Result<ValidatedBlsDoryV3CandidateStatement, BlsDoryV3CandidateError> {
        if block.network_id != self.network_id {
            return Err(BlsDoryV3CandidateError::WrongNetwork);
        }
        if proof.algorithm_version != FORGEMATRIX_V2_ALGORITHM_VERSION {
            return Err(BlsDoryV3CandidateError::AlgorithmVersion);
        }
        if proof.proof_version != FORGEMATRIX_V2_PROOF_VERSION {
            return Err(BlsDoryV3CandidateError::ProofVersion);
        }
        let manifest_digest = self.manifest.digest()?;
        if proof.model_manifest_digest != manifest_digest {
            return Err(BlsDoryV3CandidateError::ModelManifestDigest);
        }
        let descriptor = self.descriptor();
        let expected_challenge = challenge_digest(&descriptor, block, proof.nonce)
            .map_err(|_| BlsDoryV3CandidateError::ChallengeDigest)?;
        if proof.challenge_digest != expected_challenge {
            return Err(BlsDoryV3CandidateError::ChallengeDigest);
        }
        let expected_work = work_digest_from_roots(
            expected_challenge,
            self.manifest.raw_blake3_root,
            self.manifest.pcs_commitment_root,
            proof.final_activation_digest,
        );
        if proof.work_digest != expected_work {
            return Err(BlsDoryV3CandidateError::WorkDigest);
        }
        if proof.work_digest > block.target {
            return Err(BlsDoryV3CandidateError::HighHash);
        }

        let binding = algebraic_binding(
            self.network_id,
            self.record_digest,
            manifest_digest,
            block,
            proof,
        );
        let shape = StructuredForgeMatrixResearchShape::production_candidate();
        shape
            .validate_verifier_shape()
            .map_err(|_| BlsDoryV3CandidateError::ProductionGeometry)?;
        let mut transition_statements = Vec::with_capacity(PRODUCTION_V2_BANKS as usize + 1);
        transition_statements.push(shape.initialization_statement);
        transition_statements.extend_from_slice(&shape.transition_statements);
        let masks = production_masks(expected_challenge, &shape)?;
        Ok(ValidatedBlsDoryV3CandidateStatement {
            binding,
            shape,
            transition_statements,
            masks,
        })
    }

    fn validate_candidate_statement(
        &self,
        block: &BlockChallenge,
        proof: &ForgeMatrixV3CandidateProof,
    ) -> Result<ValidatedBlsDoryV3CandidateStatement, BlsDoryV3CandidateError> {
        if proof.structured_proof.is_empty()
            || proof.structured_proof.len() > MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES
        {
            return Err(BlsDoryV3CandidateError::ProofSize);
        }
        self.validate_candidate_public_statement(block, proof)
    }

    /// Verify the exact block/public fields and the real shared Dory payload.
    ///
    /// Success deliberately does not establish the final-activation BLAKE3
    /// relation and is therefore insufficient for chain admission.
    pub fn verify_algebraic_candidate(
        &self,
        block: &BlockChallenge,
        proof: &ForgeMatrixV3CandidateProof,
    ) -> Result<VerifiedBlsDoryV3AlgebraicCandidate, BlsDoryV3CandidateError> {
        let validated = self.validate_candidate_statement(block, proof)?;
        let payload = BlsDoryV3CandidatePayload::decode(&proof.structured_proof)?;
        let mask_refs = validated.masks.iter().collect::<Vec<_>>();
        let final_output = verify_algebraic_payload_with_final_output(
            &validated.binding,
            &self.trusted_model,
            &self.fixed_model,
            &validated.shape.matrix_statements,
            &validated.transition_statements,
            &mask_refs,
            validated.shape.wiring_statement,
            &payload.dory_proof,
            BLS_DORY_SHARED_PRODUCTION_VARIABLES,
            &self.setup,
        )?;
        Ok(verified_algebraic_candidate(
            validated.binding,
            &payload.dory_proof,
            final_output,
        ))
    }

    /// Verify the composed V3 research candidate. This establishes the
    /// execution/hash relation but intentionally does not create the
    /// chain-admission capability while production gates remain open.
    #[cfg(feature = "whir-prototype")]
    pub fn verify_candidate(
        &self,
        block: &BlockChallenge,
        proof: &ForgeMatrixV3CandidateProof,
    ) -> Result<VerifiedBlsDoryV3Candidate, BlsDoryV3CandidateError> {
        let validated = self.validate_candidate_statement(block, proof)?;
        let payload = BlsDoryV3CandidatePayload::decode(&proof.structured_proof)?;
        let shared_proof = BlsDorySharedLayoutProof::decode_with_variables(
            &payload.dory_proof,
            &validated.shape.matrix_statements,
            &validated.transition_statements,
            validated.shape.wiring_statement,
            BLS_DORY_SHARED_PRODUCTION_VARIABLES,
        )?;
        let mask_refs = validated.masks.iter().collect::<Vec<_>>();
        let prepared = prepare_bls_dory_shared_layout_verifier_state(
            &validated.binding,
            &self.trusted_model,
            &self.fixed_model,
            &validated.shape.matrix_statements,
            &validated.transition_statements,
            &mask_refs,
            validated.shape.wiring_statement,
            &shared_proof,
            BLS_DORY_SHARED_PRODUCTION_VARIABLES,
            &self.setup,
        )?;
        let final_output = verify_prepared_bls_dory_shared_layout_with_native_proof(
            prepared,
            proof.challenge_digest,
            proof.final_activation_digest,
            production_final_activation_len()?,
            &payload.native_blake3_proof,
            &shared_proof.opening_proof,
            &self.setup,
        )?;
        let algebraic =
            verified_algebraic_candidate(validated.binding, &payload.dory_proof, final_output);
        let mut hasher = blake3::Hasher::new_derive_key(
            "CommonFoundry/ForgeMatrix/V3/BlsDoryNativeBlake3Proof/v1",
        );
        hasher.update(&algebraic.binding());
        hasher.update(&(payload.native_blake3_proof.len() as u64).to_le_bytes());
        hasher.update(&payload.native_blake3_proof);
        Ok(VerifiedBlsDoryV3Candidate {
            algebraic,
            native_blake3_proof_digest: *hasher.finalize().as_bytes(),
        })
    }
}

#[cfg(feature = "whir-prototype")]
#[allow(clippy::too_many_arguments)]
fn validate_dory_v3_layout_v5_candidate_statement(
    network_id: [u8; 32],
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    block: &BlockChallenge,
    proof: &ForgeMatrixV3CandidateProof,
    setup: &DeterministicBlsDorySetup,
) -> Result<ValidatedBlsDoryV3LayoutV5CandidateStatement, BlsDoryV3CandidateError> {
    validate_dory_v3_layout_v5_candidate_public_envelope(network_id, block, proof)?;
    validate_dory_v3_layout_v5_record_setup_binding(authenticated, setup)?;
    authenticated.record().validate_production(setup)?;
    validate_dory_v3_layout_v5_candidate_statement_after_authority(
        network_id,
        authenticated,
        block,
        proof,
    )
}

#[cfg(feature = "whir-prototype")]
fn validate_dory_v3_layout_v5_candidate_public_envelope(
    network_id: [u8; 32],
    block: &BlockChallenge,
    proof: &ForgeMatrixV3CandidateProof,
) -> Result<(), BlsDoryV3CandidateError> {
    if network_id == [0; 32] {
        return Err(BlsDoryV3CandidateError::NetworkIdentity);
    }
    if block.network_id != network_id {
        return Err(BlsDoryV3CandidateError::WrongNetwork);
    }
    if proof.algorithm_version != DORY_V3_ALGORITHM_VERSION {
        return Err(BlsDoryV3CandidateError::AlgorithmVersion);
    }
    if proof.proof_version != DORY_V3_PROOF_VERSION {
        return Err(BlsDoryV3CandidateError::ProofVersion);
    }
    if proof.structured_proof.is_empty()
        || proof.structured_proof.len() > MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES
    {
        return Err(BlsDoryV3CandidateError::ProofSize);
    }
    Ok(())
}

/// Cheap identity comparison shared by the dormant seal and verify routes.
/// Exact production geometry remains enforced separately by
/// `validate_production`; this helper exists so a substituted setup is rejected
/// before any proof parsing or verification work.
#[cfg(feature = "whir-prototype")]
pub(crate) fn validate_dory_v3_layout_v5_record_setup_binding(
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDoryV3CandidateError> {
    let record = authenticated.record();
    if record.setup_identity().into_bytes() != setup.identity()
        || usize::try_from(record.padded_variables()).ok() != Some(setup.max_log_n())
    {
        return Err(DoryV3ModelCommitmentRecordError::SetupIdentityMismatch.into());
    }
    Ok(())
}

#[cfg(feature = "whir-prototype")]
fn validate_dory_v3_layout_v5_candidate_statement_after_authority(
    network_id: [u8; 32],
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    block: &BlockChallenge,
    proof: &ForgeMatrixV3CandidateProof,
) -> Result<ValidatedBlsDoryV3LayoutV5CandidateStatement, BlsDoryV3CandidateError> {
    let transcript =
        DoryV3TranscriptContext::from_bank_authenticated_record(network_id, authenticated)?;
    if proof.model_manifest_digest != transcript.manifest_digest().into_bytes() {
        return Err(BlsDoryV3CandidateError::ModelManifestDigest);
    }
    let challenge = transcript.challenge_context(block, proof.nonce)?;
    if proof.challenge_digest != challenge.digest() {
        return Err(BlsDoryV3CandidateError::ChallengeDigest);
    }
    if proof.work_digest
        != transcript.work_digest(proof.challenge_digest, proof.final_activation_digest)
    {
        return Err(BlsDoryV3CandidateError::WorkDigest);
    }
    if proof.work_digest > block.target {
        return Err(BlsDoryV3CandidateError::HighHash);
    }

    let shape = StructuredForgeMatrixResearchShape::production_candidate();
    shape
        .validate_verifier_shape()
        .map_err(|_| BlsDoryV3CandidateError::ProductionGeometry)?;
    let mut transition_statements = Vec::with_capacity(PRODUCTION_V2_BANKS as usize + 1);
    transition_statements.push(shape.initialization_statement);
    transition_statements.extend_from_slice(&shape.transition_statements);
    let masks = production_dory_v3_masks(proof.challenge_digest, &shape)?;
    Ok(ValidatedBlsDoryV3LayoutV5CandidateStatement {
        binding: transcript.algebraic_binding(block, proof)?,
        challenge_digest: challenge.digest(),
        shape,
        transition_statements,
        masks,
    })
}

#[cfg(all(test, feature = "whir-prototype"))]
pub(crate) fn validate_dory_v3_layout_v5_candidate_statement_for_test(
    network_id: [u8; 32],
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    block: &BlockChallenge,
    proof: &ForgeMatrixV3CandidateProof,
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDoryV3CandidateError> {
    validate_dory_v3_layout_v5_candidate_public_envelope(network_id, block, proof)?;
    authenticated.record().validate()?;
    validate_dory_v3_layout_v5_record_setup_binding(authenticated, setup)?;
    validate_dory_v3_layout_v5_candidate_statement_after_authority(
        network_id,
        authenticated,
        block,
        proof,
    )?;
    Ok(())
}

/// Decode the existing CP02 envelope and its V5 Dory frame with the exact
/// production topology. There is deliberately no V4 retry on any failure.
#[cfg(feature = "whir-prototype")]
pub(crate) fn decode_dory_v3_layout_v5_candidate_payload(
    encoded: &[u8],
    context: &BlsDorySharedLayoutV5Context,
) -> Result<(BlsDorySharedLayoutV5Proof, BlsDoryV3CandidatePayload), BlsDoryV3CandidateError> {
    let payload = BlsDoryV3CandidatePayload::decode(encoded)?;
    let shape = StructuredForgeMatrixResearchShape::production_candidate();
    let transition_statements = [
        shape.initialization_statement,
        shape.transition_statements[0],
        shape.transition_statements[1],
        shape.transition_statements[2],
    ];
    let shared_proof = BlsDorySharedLayoutV5Proof::decode_with_context(
        &payload.dory_proof,
        context,
        &shape.matrix_statements,
        &transition_statements,
        shape.wiring_statement,
    )?;
    Ok((shared_proof, payload))
}

/// Verify only the dormant Record-V2/Layout-V5 research candidate route.
/// Failure to parse or verify V5 is terminal; the legacy V4 route is never
/// retried or reinterpreted.
#[cfg(feature = "whir-prototype")]
#[allow(dead_code)]
pub(crate) fn verify_bls_dory_v3_layout_v5_candidate(
    network_id: [u8; 32],
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    block: &BlockChallenge,
    proof: &ForgeMatrixV3CandidateProof,
    setup: &DeterministicBlsDorySetup,
) -> Result<VerifiedBlsDoryV3LayoutV5Candidate, BlsDoryV3CandidateError> {
    let validated = validate_dory_v3_layout_v5_candidate_statement(
        network_id,
        authenticated,
        block,
        proof,
        setup,
    )?;
    let context =
        BlsDorySharedLayoutV5Context::from_bank_authenticated_record(authenticated, setup)?;
    let (shared_proof, payload) =
        decode_dory_v3_layout_v5_candidate_payload(&proof.structured_proof, &context)?;
    let component_binding = context.fixed_model_binding(&validated.binding)?;
    let mask_refs = validated.masks.iter().collect::<Vec<_>>();
    let prepared = prepare_bls_dory_shared_layout_v5_verifier_state(
        &validated.binding,
        authenticated,
        context,
        component_binding,
        &validated.shape.matrix_statements,
        &validated.transition_statements,
        &mask_refs,
        validated.shape.wiring_statement,
        &shared_proof,
        setup,
    )?;
    let final_output = verify_prepared_bls_dory_shared_layout_v5_with_native_proof(
        prepared,
        validated.challenge_digest,
        proof.final_activation_digest,
        BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES,
        &payload.native_blake3_proof,
        setup,
    )?;

    let mut dory_hasher =
        blake3::Hasher::new_derive_key("CommonFoundry/ForgeMatrix/V3/LayoutV5DoryProof/v1");
    dory_hasher.update(&validated.binding);
    dory_hasher.update(&(payload.dory_proof.len() as u64).to_le_bytes());
    dory_hasher.update(&payload.dory_proof);
    let mut native_hasher =
        blake3::Hasher::new_derive_key("CommonFoundry/ForgeMatrix/V3/LayoutV5NativeBlake3Proof/v1");
    native_hasher.update(&validated.binding);
    native_hasher.update(&(payload.native_blake3_proof.len() as u64).to_le_bytes());
    native_hasher.update(&payload.native_blake3_proof);
    Ok(VerifiedBlsDoryV3LayoutV5Candidate {
        binding: validated.binding,
        dory_proof_digest: *dory_hasher.finalize().as_bytes(),
        native_blake3_proof_digest: *native_hasher.finalize().as_bytes(),
        final_output,
    })
}

#[cfg(feature = "whir-prototype")]
fn production_dory_v3_masks(
    challenge_digest: [u8; 32],
    shape: &StructuredForgeMatrixResearchShape,
) -> Result<Vec<StructuredMaskPolynomial>, BlsDoryV3CandidateError> {
    let mut masks = Vec::with_capacity(shape.transition_statements.len() + 1);
    masks.push(StructuredMaskPolynomial::from_dory_v3_virtual_challenge(
        &challenge_digest,
        shape.initialization_statement.rows,
        shape.initialization_statement.cols,
    )?);
    let mut first_layer = 0_u32;
    for statement in &shape.transition_statements {
        masks.push(
            StructuredMaskPolynomial::from_dory_v3_challenge_at_layer_offset(
                &challenge_digest,
                first_layer,
                statement.layers,
                statement.rows,
                statement.cols,
            )?,
        );
        first_layer = first_layer
            .checked_add(
                u32::try_from(statement.layers)
                    .map_err(|_| BlsDoryV3CandidateError::ProductionGeometry)?,
            )
            .ok_or(BlsDoryV3CandidateError::ProductionGeometry)?;
    }
    Ok(masks)
}

fn verified_algebraic_candidate(
    binding: [u8; 32],
    encoded_proof: &[u8],
    final_output: VerifiedBlsDoryFinalOutputOpening,
) -> VerifiedBlsDoryV3AlgebraicCandidate {
    let mut proof_hasher =
        blake3::Hasher::new_derive_key("CommonFoundry/ForgeMatrix/V3/BlsDoryAlgebraicProof/v1");
    proof_hasher.update(&binding);
    proof_hasher.update(&(encoded_proof.len() as u64).to_le_bytes());
    proof_hasher.update(encoded_proof);
    VerifiedBlsDoryV3AlgebraicCandidate {
        binding,
        proof_digest: *proof_hasher.finalize().as_bytes(),
        final_output,
    }
}

#[cfg(feature = "whir-prototype")]
fn production_final_activation_len() -> Result<usize, BlsDoryV3CandidateError> {
    usize::try_from(PRODUCTION_V2_BATCH)
        .ok()
        .and_then(|rows| {
            usize::try_from(PRODUCTION_V2_DIMENSION)
                .ok()
                .and_then(|cols| rows.checked_mul(cols))
        })
        .ok_or(BlsDoryV3CandidateError::ProductionGeometry)
}

#[cfg(feature = "whir-prototype")]
fn validate_production_witness_shape(
    shape: &StructuredForgeMatrixResearchShape,
    witness: &BlsDoryV3CandidateWitness<'_>,
) -> Result<(), BlsDoryV3CandidateError> {
    if witness.matrices.len() != shape.matrix_statements.len()
        || witness.transitions.len() != shape.transition_statements.len() + 1
    {
        return Err(BlsDoryV3CandidateError::WitnessShape);
    }
    for (matrix, statement) in witness.matrices.iter().zip(&shape.matrix_statements) {
        let [activation_len, _, accumulator_len] = statement
            .table_lengths()
            .map_err(|_| BlsDoryV3CandidateError::WitnessShape)?;
        if matrix.activations.len() != activation_len
            || matrix.accumulators.len() != accumulator_len
        {
            return Err(BlsDoryV3CandidateError::WitnessShape);
        }
    }
    for (transition, statement) in witness
        .transitions
        .iter()
        .zip(std::iter::once(&shape.initialization_statement).chain(&shape.transition_statements))
    {
        let expected = statement
            .elements()
            .map_err(|_| BlsDoryV3CandidateError::WitnessShape)?;
        if !transition_witness_has_length(transition, expected) {
            return Err(BlsDoryV3CandidateError::WitnessShape);
        }
    }
    let wiring_elements = shape
        .wiring_statement
        .elements()
        .map_err(|_| BlsDoryV3CandidateError::WitnessShape)?;
    if witness.wiring_inputs.len() != wiring_elements
        || witness.wiring_outputs.len() != wiring_elements
    {
        return Err(BlsDoryV3CandidateError::WitnessShape);
    }
    Ok(())
}

#[cfg(feature = "whir-prototype")]
fn transition_witness_has_length(witness: &StructuredTransitionWitness, expected: usize) -> bool {
    [
        witness.accumulators.len(),
        witness.masks.len(),
        witness.encoded.len(),
        witness.square_quotients.len(),
        witness.square_remainders.len(),
        witness.cube_quotients.len(),
        witness.cube_remainders.len(),
        witness.output_quotients.len(),
        witness.output_remainders.len(),
        witness.negative.len(),
        witness.activations.len(),
    ]
    .into_iter()
    .all(|length| length == expected)
}

#[cfg(feature = "whir-prototype")]
fn production_final_activation(wiring_outputs: &[i64]) -> Result<Vec<u8>, BlsDoryV3CandidateError> {
    let final_len = production_final_activation_len()?;
    let total_len = usize::try_from(PRODUCTION_V2_LAYERS)
        .ok()
        .and_then(|layers| final_len.checked_mul(layers))
        .ok_or(BlsDoryV3CandidateError::ProductionGeometry)?;
    if wiring_outputs.len() != total_len {
        return Err(BlsDoryV3CandidateError::WitnessShape);
    }
    centered_activation_bytes(&wiring_outputs[total_len - final_len..])
}

#[cfg(feature = "whir-prototype")]
fn centered_activation_bytes(values: &[i64]) -> Result<Vec<u8>, BlsDoryV3CandidateError> {
    values
        .iter()
        .map(|value| {
            value
                .checked_add(125)
                .and_then(|shifted| u8::try_from(shifted).ok())
                .filter(|byte| *byte <= 250)
                .ok_or(BlsDoryV3CandidateError::FinalActivation)
        })
        .collect()
}

fn validate_production_record(
    record: &BlsDoryModelCommitmentRecord,
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDoryV3CandidateError> {
    let manifest = record.manifest;
    let model = &record.model_pcs_identity;
    manifest.verify_pcs_identity(model)?;
    if setup.max_log_n() != BLS_DORY_SHARED_PRODUCTION_VARIABLES
        || usize::try_from(record.padded_variables).ok()
            != Some(BLS_DORY_SHARED_PRODUCTION_VARIABLES)
        || manifest.model_version != 2
        || manifest.batch != PRODUCTION_V2_BATCH
        || manifest.dimension != PRODUCTION_V2_DIMENSION
        || manifest.layers != PRODUCTION_V2_LAYERS
        || model.model_version != manifest.model_version
        || model.batch != PRODUCTION_V2_BATCH
        || model.dimension != PRODUCTION_V2_DIMENSION
        || model.layers_per_bank != PRODUCTION_V2_LAYERS_PER_BANK
        || model.weight_bank_commitments.len() != PRODUCTION_V2_BANKS as usize
    {
        return Err(BlsDoryV3CandidateError::ProductionGeometry);
    }
    Ok(())
}

fn production_masks(
    challenge: [u8; 32],
    shape: &StructuredForgeMatrixResearchShape,
) -> Result<Vec<StructuredMaskPolynomial>, StructuredTransitionError> {
    let mut masks = Vec::with_capacity(PRODUCTION_V2_BANKS as usize + 1);
    masks.push(StructuredMaskPolynomial::from_virtual_challenge(
        &challenge,
        shape.initialization_statement.rows,
        shape.initialization_statement.cols,
    )?);
    for (bank, statement) in shape.transition_statements.iter().enumerate() {
        let first_layer = u32::try_from(bank)
            .ok()
            .and_then(|bank| bank.checked_mul(PRODUCTION_V2_LAYERS_PER_BANK))
            .ok_or(StructuredTransitionError::ArithmeticOverflow)?;
        masks.push(StructuredMaskPolynomial::from_challenge_at_layer_offset(
            &challenge,
            first_layer,
            statement.layers,
            statement.rows,
            statement.cols,
        )?);
    }
    Ok(masks)
}

#[cfg(feature = "whir-prototype")]
fn checked_candidate_scratch_sum(values: &[u64]) -> Result<u64, BlsDoryV3CandidateError> {
    values.iter().try_fold(0_u64, |sum, value| {
        sum.checked_add(*value)
            .ok_or(BlsDoryV3CandidateError::ScratchProjection)
    })
}

#[cfg(feature = "whir-prototype")]
fn projected_candidate_scratch_space()
-> Result<BlsDoryV3CandidateScratchProjection, BlsDoryV3CandidateError> {
    let shared = projected_shared_production_scratch_bytes()
        .map_err(|_| BlsDoryV3CandidateError::ScratchProjection)?;
    let transition_source_bytes = projected_production_transition_range_source_bytes()
        .map_err(|_| BlsDoryV3CandidateError::ScratchProjection)?;
    let logup_lineage_peak_bytes = projected_production_range_logup_early_lineage_peak_bytes()
        .map_err(|_| BlsDoryV3CandidateError::ScratchProjection)?;
    let native = projected_bls_dory_blake3_production_resources()
        .map_err(|_| BlsDoryV3CandidateError::ScratchProjection)?;

    // The fixed-base artifact belongs to `prepared_model` and already exists
    // when the candidate preflight measures free space, so exclude it. The
    // shared projection does not expose the three prepared weight artifacts
    // separately; leaving them in this value deliberately overstates future
    // scratch allocation rather than risking an undercount.
    let conservative_future_retained_source_bytes = shared
        .retained_source_bytes
        .checked_sub(shared.fixed_base_source_bytes)
        .ok_or(BlsDoryV3CandidateError::ScratchProjection)?;
    let shared_construction_peak_bytes = checked_candidate_scratch_sum(&[
        shared.matrix_source_bytes,
        shared.multiplicity_source_bytes,
        transition_source_bytes,
        logup_lineage_peak_bytes,
    ])?;
    let shared_aggregate_peak_bytes = shared
        .aggregate_peak_bytes
        .checked_sub(shared.fixed_base_source_bytes)
        .ok_or(BlsDoryV3CandidateError::ScratchProjection)?;

    // The prepared shared state remains live through both native sumchecks.
    // Their standalone projections therefore need the retained shared sources
    // added explicitly before comparing phase peaks.
    let native_execution_peak_bytes = conservative_future_retained_source_bytes
        .checked_add(native.execution_stage_projected_peak_scratch_bytes)
        .ok_or(BlsDoryV3CandidateError::ScratchProjection)?;
    let native_adjacency_peak_bytes = conservative_future_retained_source_bytes
        .checked_add(native.adjacency_stage_projected_peak_scratch_bytes)
        .ok_or(BlsDoryV3CandidateError::ScratchProjection)?;
    let native_aggregate_peak_bytes = native
        .aggregate_with_transpose_coexistence_bytes
        .checked_sub(shared.fixed_base_source_bytes)
        .ok_or(BlsDoryV3CandidateError::ScratchProjection)?;
    let required_free_bytes = [
        shared_construction_peak_bytes,
        shared_aggregate_peak_bytes,
        native_execution_peak_bytes,
        native_adjacency_peak_bytes,
        native_aggregate_peak_bytes,
        native.provisional_scratch_gate_bytes,
    ]
    .into_iter()
    .max()
    .ok_or(BlsDoryV3CandidateError::ScratchProjection)?;

    Ok(BlsDoryV3CandidateScratchProjection {
        conservative_future_retained_source_bytes,
        shared_construction_peak_bytes,
        shared_aggregate_peak_bytes,
        native_execution_peak_bytes,
        native_adjacency_peak_bytes,
        native_aggregate_peak_bytes,
        required_free_bytes,
    })
}

#[cfg(feature = "whir-prototype")]
fn preflight_candidate_scratch(scratch_directory: &Path) -> Result<(), BlsDoryV3CandidateError> {
    let projection = projected_candidate_scratch_space()?;
    let available = fs2::available_space(scratch_directory)
        .map_err(BlsDoryV3CandidateError::ScratchSpaceQuery)?;
    ensure_candidate_scratch_available(projection.required_free_bytes, available)
}

#[cfg(feature = "whir-prototype")]
fn ensure_candidate_scratch_available(
    required: u64,
    available: u64,
) -> Result<(), BlsDoryV3CandidateError> {
    if available < required {
        return Err(BlsDoryV3CandidateError::InsufficientScratch {
            required,
            available,
        });
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(crate) fn verify_algebraic_payload(
    binding: &[u8],
    trusted_model: &ModelPcsIdentity,
    fixed_model: &BlsDoryFixedModelIdentity,
    matrix_statements: &[StructuredMatrixStatement],
    transition_statements: &[StructuredTransitionStatement],
    masks: &[&StructuredMaskPolynomial],
    wiring_statement: StructuredWiringStatement,
    encoded: &[u8],
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDorySharedLayoutError> {
    verify_algebraic_payload_with_final_output(
        binding,
        trusted_model,
        fixed_model,
        matrix_statements,
        transition_statements,
        masks,
        wiring_statement,
        encoded,
        padded_variables,
        setup,
    )
    .map(|_| ())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_algebraic_payload_with_final_output(
    binding: &[u8],
    trusted_model: &ModelPcsIdentity,
    fixed_model: &BlsDoryFixedModelIdentity,
    matrix_statements: &[StructuredMatrixStatement],
    transition_statements: &[StructuredTransitionStatement],
    masks: &[&StructuredMaskPolynomial],
    wiring_statement: StructuredWiringStatement,
    encoded: &[u8],
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<VerifiedBlsDoryFinalOutputOpening, BlsDorySharedLayoutError> {
    let proof = BlsDorySharedLayoutProof::decode_with_variables(
        encoded,
        matrix_statements,
        transition_statements,
        wiring_statement,
        padded_variables,
    )?;
    verify_bls_dory_shared_layout_with_final_output_at_variables(
        binding,
        trusted_model,
        fixed_model,
        matrix_statements,
        transition_statements,
        masks,
        wiring_statement,
        &proof,
        padded_variables,
        setup,
    )
}

fn algebraic_binding(
    network_id: [u8; 32],
    record_digest: [u8; 32],
    manifest_digest: [u8; 32],
    block: &BlockChallenge,
    proof: &ForgeMatrixV3CandidateProof,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(ALGEBRAIC_BINDING_DOMAIN);
    hasher.update(&ALGEBRAIC_BINDING_VERSION.to_le_bytes());
    hasher.update(&POW_TYPE_V3_CANDIDATE.to_le_bytes());
    hasher.update(&network_id);
    hasher.update(&proof.algorithm_version.to_le_bytes());
    hasher.update(&proof.proof_version.to_le_bytes());
    hasher.update(&record_digest);
    hasher.update(&manifest_digest);
    hasher.update(&block.previous_block);
    hasher.update(&block.transaction_root);
    hasher.update(&block.height.to_le_bytes());
    hasher.update(&block.timestamp.to_le_bytes());
    hasher.update(&block.target);
    hasher.update(&proof.nonce.to_le_bytes());
    hasher.update(&proof.challenge_digest);
    hasher.update(&proof.final_activation_digest);
    hasher.update(&proof.work_digest);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "whir-prototype")]
    use dory_pcs::primitives::arithmetic::Group;

    #[cfg(feature = "whir-prototype")]
    use crate::dory_bls12_381_prototype::{BlsDoryGt, deterministic_bls_dory_setup};

    fn block() -> BlockChallenge {
        BlockChallenge {
            network_id: [0x31; 32],
            previous_block: [0x42; 32],
            transaction_root: [0x53; 32],
            height: 17,
            timestamp: 23,
            target: [0xff; 32],
        }
    }

    fn proof() -> ForgeMatrixV3CandidateProof {
        ForgeMatrixV3CandidateProof {
            algorithm_version: FORGEMATRIX_V2_ALGORITHM_VERSION,
            proof_version: FORGEMATRIX_V2_PROOF_VERSION,
            nonce: 29,
            model_manifest_digest: [0x64; 32],
            challenge_digest: [0x75; 32],
            final_activation_digest: [0x86; 32],
            work_digest: [0x97; 32],
            structured_proof: vec![1],
        }
    }

    #[cfg(feature = "whir-prototype")]
    fn execution_context_verifier(
        record_digest: [u8; 32],
        setup_variables: usize,
    ) -> BlsDoryV3AlgebraicVerifier {
        let setup = Arc::new(deterministic_bls_dory_setup(setup_variables).unwrap());
        let base_input_bytes = u64::from(PRODUCTION_V2_BATCH * PRODUCTION_V2_DIMENSION);
        let bytes_per_layer = u64::from(PRODUCTION_V2_DIMENSION).pow(2);
        let payload_bytes = base_input_bytes
            + u64::from(PRODUCTION_V2_LAYERS)
                .checked_mul(bytes_per_layer)
                .unwrap();
        let manifest = ModelBankManifest {
            model_version: 2,
            dimension: PRODUCTION_V2_DIMENSION,
            batch: PRODUCTION_V2_BATCH,
            layers: PRODUCTION_V2_LAYERS,
            base_input_bytes,
            bytes_per_layer,
            payload_bytes,
            raw_blake3_root: [0x81; 32],
            layer_roots_aggregate: [0x82; 32],
            pcs_parameter_digest: [0x83; 32],
            pcs_commitment_root: [0x84; 32],
        };
        let trusted_model = ModelPcsIdentity {
            model_version: 2,
            batch: PRODUCTION_V2_BATCH,
            dimension: PRODUCTION_V2_DIMENSION,
            layers_per_bank: PRODUCTION_V2_LAYERS_PER_BANK,
            model_byte_root: manifest.raw_blake3_root,
            pcs_suite_parameter_digest: manifest.pcs_parameter_digest,
            base_input_commitment: [0x85; 32],
            weight_bank_commitments: vec![[0x86; 32]; PRODUCTION_V2_BANKS as usize],
        };
        let fixed_model = BlsDoryFixedModelIdentity {
            protocol_version: crate::dory_bls12_381_layout::BLS_DORY_FIXED_MODEL_IDENTITY_VERSION,
            model_pcs_identity_digest: [0x87; 32],
            setup_identity: setup.identity(),
            base_input_commitment: BlsDoryGt::identity(),
            weight_bank_commitments: Vec::new(),
        };
        BlsDoryV3AlgebraicVerifier {
            network_id: [0x31; 32],
            manifest,
            trusted_model,
            fixed_model,
            record_digest,
            setup,
        }
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn production_candidate_scratch_projection_covers_every_live_phase() {
        let projection = projected_candidate_scratch_space().unwrap();

        assert_eq!(
            projection.conservative_future_retained_source_bytes,
            25_887_962_384
        );
        assert_eq!(projection.shared_construction_peak_bytes, 39_868_223_240);
        assert_eq!(projection.shared_aggregate_peak_bytes, 29_185_638_896);
        assert_eq!(projection.native_execution_peak_bytes, 52_899_281_168);
        assert_eq!(projection.native_adjacency_peak_bytes, 48_721_754_384);
        assert_eq!(projection.native_aggregate_peak_bytes, 38_407_962_284);
        assert_eq!(projection.required_free_bytes, 53_687_091_200);
        assert!(
            [
                projection.shared_construction_peak_bytes,
                projection.shared_aggregate_peak_bytes,
                projection.native_execution_peak_bytes,
                projection.native_adjacency_peak_bytes,
                projection.native_aggregate_peak_bytes,
            ]
            .into_iter()
            .all(|phase| projection.required_free_bytes >= phase)
        );
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn candidate_scratch_boundary_and_projection_overflow_fail_closed() {
        let required = projected_candidate_scratch_space()
            .unwrap()
            .required_free_bytes;

        ensure_candidate_scratch_available(required, required).unwrap();
        ensure_candidate_scratch_available(required, u64::MAX).unwrap();
        assert!(matches!(
            ensure_candidate_scratch_available(required, required - 1),
            Err(BlsDoryV3CandidateError::InsufficientScratch {
                required: observed_required,
                available
            }) if observed_required == required && available == required - 1
        ));
        assert!(matches!(
            checked_candidate_scratch_sum(&[u64::MAX, 1]),
            Err(BlsDoryV3CandidateError::ScratchProjection)
        ));
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn execution_artifact_context_uses_only_pinned_candidate_identities() {
        let verifier = execution_context_verifier([0x91; 32], 6);
        let candidate = block();
        let nonce = 29;
        let context = verifier
            .execution_artifact_context(&candidate, nonce)
            .unwrap();
        let expected_challenge =
            challenge_digest(&verifier.descriptor(), &candidate, nonce).unwrap();

        assert_eq!(context.network_identity(), verifier.network_id);
        assert_eq!(context.model_record_identity(), verifier.record_digest);
        assert_eq!(context.setup_identity(), verifier.setup.identity());
        assert_eq!(context.challenge_identity(), expected_challenge);

        let changed_nonce = verifier
            .execution_artifact_context(&candidate, nonce + 1)
            .unwrap();
        assert_eq!(changed_nonce.network_identity(), context.network_identity());
        assert_eq!(
            changed_nonce.model_record_identity(),
            context.model_record_identity()
        );
        assert_eq!(changed_nonce.setup_identity(), context.setup_identity());
        assert_ne!(
            changed_nonce.challenge_identity(),
            context.challenge_identity()
        );

        let mut changed_block = candidate;
        changed_block.previous_block[0] ^= 1;
        let changed_statement = verifier
            .execution_artifact_context(&changed_block, nonce)
            .unwrap();
        assert_ne!(
            changed_statement.challenge_identity(),
            context.challenge_identity()
        );

        let changed_model = execution_context_verifier([0x92; 32], 6)
            .execution_artifact_context(&candidate, nonce)
            .unwrap();
        assert_eq!(
            changed_model.challenge_identity(),
            context.challenge_identity()
        );
        assert_ne!(
            changed_model.model_record_identity(),
            context.model_record_identity()
        );

        let changed_setup = execution_context_verifier([0x91; 32], 7)
            .execution_artifact_context(&candidate, nonce)
            .unwrap();
        assert_eq!(
            changed_setup.challenge_identity(),
            context.challenge_identity()
        );
        assert_ne!(changed_setup.setup_identity(), context.setup_identity());
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn execution_artifact_context_rejects_mismatched_or_invalid_pinned_identity() {
        let verifier = execution_context_verifier([0x91; 32], 6);
        let mut wrong_network = block();
        wrong_network.network_id[0] ^= 1;
        assert!(matches!(
            verifier.execution_artifact_context(&wrong_network, 29),
            Err(BlsDoryV3CandidateError::WrongNetwork)
        ));

        let invalid_model = execution_context_verifier([0; 32], 6);
        assert!(matches!(
            invalid_model.execution_artifact_context(&block(), 29),
            Err(BlsDoryV3CandidateError::ExecutionArtifact(
                BlsDoryExecutionAccumulatorArtifactError::InvalidContext
            ))
        ));
    }

    #[test]
    fn algebraic_binding_commits_every_block_and_public_proof_field() {
        let network = [0x31; 32];
        let record = [0xa8; 32];
        let manifest = [0xb9; 32];
        let base_block = block();
        let base_proof = proof();
        let expected = algebraic_binding(network, record, manifest, &base_block, &base_proof);

        type Mutation = fn(&mut BlockChallenge, &mut ForgeMatrixV3CandidateProof);
        let mutations: [Mutation; 11] = [
            |block, _| block.previous_block[0] ^= 1,
            |block, _| block.transaction_root[0] ^= 1,
            |block, _| block.height ^= 1,
            |block, _| block.timestamp ^= 1,
            |block, _| block.target[0] ^= 1,
            |_, proof| proof.algorithm_version ^= 1,
            |_, proof| proof.proof_version ^= 1,
            |_, proof| proof.nonce ^= 1,
            |_, proof| proof.challenge_digest[0] ^= 1,
            |_, proof| proof.final_activation_digest[0] ^= 1,
            |_, proof| proof.work_digest[0] ^= 1,
        ];
        for mutate in mutations {
            let mut changed_block = base_block;
            let mut changed_proof = base_proof.clone();
            mutate(&mut changed_block, &mut changed_proof);
            assert_ne!(
                algebraic_binding(network, record, manifest, &changed_block, &changed_proof),
                expected
            );
        }
        assert_ne!(
            algebraic_binding([0x30; 32], record, manifest, &base_block, &base_proof),
            expected
        );
        assert_ne!(
            algebraic_binding(network, [0xa9; 32], manifest, &base_block, &base_proof),
            expected
        );
        assert_ne!(
            algebraic_binding(network, record, [0xb8; 32], &base_block, &base_proof),
            expected
        );
    }

    #[test]
    fn pow_parameters_still_have_no_v3_selector() {
        let parameters =
            crate::PowParameters::V2Reference(crate::v2_test_reference().unwrap().descriptor());
        assert!(matches!(parameters, crate::PowParameters::V2Reference(_)));
    }

    #[test]
    fn candidate_payload_codec_is_canonical_and_bounded() {
        let payload = BlsDoryV3CandidatePayload {
            dory_proof: vec![0x31; 7],
            native_blake3_proof: vec![0x42; 11],
        };
        let encoded = payload.encode().unwrap();
        assert_eq!(encoded.len(), CANDIDATE_PAYLOAD_HEADER_BYTES + 18);
        assert_eq!(
            BlsDoryV3CandidatePayload::decode(&encoded).unwrap(),
            payload
        );

        let mut malformed = encoded.clone();
        malformed[0] ^= 1;
        assert!(matches!(
            BlsDoryV3CandidatePayload::decode(&malformed),
            Err(BlsDoryV3CandidateError::Payload)
        ));
        let mut malformed = encoded.clone();
        malformed[8..10].copy_from_slice(&(CANDIDATE_PAYLOAD_VERSION + 1).to_le_bytes());
        assert!(matches!(
            BlsDoryV3CandidatePayload::decode(&malformed),
            Err(BlsDoryV3CandidateError::Payload)
        ));
        let mut legacy = encoded.clone();
        legacy[..8].copy_from_slice(b"CFV3CP01");
        legacy[8..10].copy_from_slice(&1_u16.to_le_bytes());
        assert!(matches!(
            BlsDoryV3CandidatePayload::decode(&legacy),
            Err(BlsDoryV3CandidateError::Payload)
        ));
        let mut malformed = encoded.clone();
        malformed[10..14].copy_from_slice(&0_u32.to_le_bytes());
        assert!(matches!(
            BlsDoryV3CandidatePayload::decode(&malformed),
            Err(BlsDoryV3CandidateError::Payload)
        ));
        let mut malformed = encoded.clone();
        malformed[14..18].copy_from_slice(&0_u32.to_le_bytes());
        assert!(matches!(
            BlsDoryV3CandidatePayload::decode(&malformed),
            Err(BlsDoryV3CandidateError::Payload)
        ));
        let mut malformed = encoded.clone();
        malformed[14..18].copy_from_slice(&12_u32.to_le_bytes());
        assert!(matches!(
            BlsDoryV3CandidatePayload::decode(&malformed),
            Err(BlsDoryV3CandidateError::Payload)
        ));
        assert!(matches!(
            BlsDoryV3CandidatePayload::decode(&encoded[..encoded.len() - 1]),
            Err(BlsDoryV3CandidateError::Payload)
        ));
        let mut malformed = encoded.clone();
        malformed.push(0);
        assert!(matches!(
            BlsDoryV3CandidatePayload::decode(&malformed),
            Err(BlsDoryV3CandidateError::Payload)
        ));

        let exact = BlsDoryV3CandidatePayload {
            dory_proof: vec![1],
            native_blake3_proof: vec![
                2;
                MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES
                    - CANDIDATE_PAYLOAD_HEADER_BYTES
                    - 1
            ],
        };
        assert_eq!(
            exact.encode().unwrap().len(),
            MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES
        );
        let over = BlsDoryV3CandidatePayload {
            dory_proof: vec![1],
            native_blake3_proof: vec![
                2;
                MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES
                    - CANDIDATE_PAYLOAD_HEADER_BYTES
            ],
        };
        assert!(matches!(
            over.encode(),
            Err(BlsDoryV3CandidateError::ProofSize)
        ));
    }

    #[cfg(feature = "whir-prototype")]
    #[test]
    fn layout_v5_candidate_masks_use_only_v3_domains_and_global_bank_offsets() {
        let challenge = [0x6d; 32];
        let shape = StructuredForgeMatrixResearchShape::production_candidate();
        let masks = production_dory_v3_masks(challenge, &shape).unwrap();
        assert_eq!(masks.len(), PRODUCTION_V2_BANKS as usize + 1);
        assert_eq!(
            masks[0],
            StructuredMaskPolynomial::from_dory_v3_virtual_challenge(
                &challenge,
                shape.initialization_statement.rows,
                shape.initialization_statement.cols,
            )
            .unwrap()
        );
        for (bank, statement) in shape.transition_statements.iter().enumerate() {
            let first_layer = u32::try_from(bank)
                .unwrap()
                .checked_mul(PRODUCTION_V2_LAYERS_PER_BANK)
                .unwrap();
            assert_eq!(
                masks[bank + 1],
                StructuredMaskPolynomial::from_dory_v3_challenge_at_layer_offset(
                    &challenge,
                    first_layer,
                    statement.layers,
                    statement.rows,
                    statement.cols,
                )
                .unwrap()
            );
        }
        assert_ne!(
            masks[0],
            StructuredMaskPolynomial::from_virtual_challenge(
                &challenge,
                shape.initialization_statement.rows,
                shape.initialization_statement.cols,
            )
            .unwrap()
        );
        assert_ne!(
            masks[1],
            StructuredMaskPolynomial::from_challenge_at_layer_offset(
                &challenge,
                0,
                shape.transition_statements[0].layers,
                shape.transition_statements[0].rows,
                shape.transition_statements[0].cols,
            )
            .unwrap()
        );

        type VerifyEntry =
            fn(
                [u8; 32],
                &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
                &BlockChallenge,
                &ForgeMatrixV3CandidateProof,
                &DeterministicBlsDorySetup,
            ) -> Result<VerifiedBlsDoryV3LayoutV5Candidate, BlsDoryV3CandidateError>;
        let verify: VerifyEntry = verify_bls_dory_v3_layout_v5_candidate;
        let _ = verify;
    }

    #[cfg(feature = "whir-prototype")]
    fn transition_witness(length: usize) -> StructuredTransitionWitness {
        StructuredTransitionWitness {
            accumulators: vec![0; length],
            masks: vec![0; length],
            encoded: vec![0; length],
            square_quotients: vec![0; length],
            square_remainders: vec![0; length],
            cube_quotients: vec![0; length],
            cube_remainders: vec![0; length],
            output_quotients: vec![0; length],
            output_remainders: vec![0; length],
            negative: vec![0; length],
            activations: vec![0; length],
        }
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn centered_activation_encoding_is_exact_and_checked() {
        assert_eq!(
            centered_activation_bytes(&[-125, 0, 125]).unwrap(),
            [0, 125, 250]
        );
        for invalid in [-126, 126, i64::MIN, i64::MAX] {
            assert!(matches!(
                centered_activation_bytes(&[invalid]),
                Err(BlsDoryV3CandidateError::FinalActivation)
            ));
        }
        assert!(matches!(
            production_final_activation(&[]),
            Err(BlsDoryV3CandidateError::WitnessShape)
        ));
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn candidate_witness_shape_rejects_short_counts_and_tables() {
        let shape = StructuredForgeMatrixResearchShape::production_candidate();
        let missing = BlsDoryV3CandidateWitness {
            matrices: &[],
            transitions: &[],
            wiring_inputs: &[],
            wiring_outputs: &[],
        };
        assert!(matches!(
            validate_production_witness_shape(&shape, &missing),
            Err(BlsDoryV3CandidateError::WitnessShape)
        ));

        let empty = BlsDoryV3CandidateMatrixWitness {
            activations: &[],
            accumulators: &[],
        };
        let matrices = [empty; 3];
        let transitions = (0..4).map(|_| transition_witness(0)).collect::<Vec<_>>();
        let witness = BlsDoryV3CandidateWitness {
            matrices: &matrices,
            transitions: &transitions,
            wiring_inputs: &[],
            wiring_outputs: &[],
        };
        assert!(matches!(
            validate_production_witness_shape(&shape, &witness),
            Err(BlsDoryV3CandidateError::WitnessShape)
        ));

        let mut transition = transition_witness(1);
        assert!(transition_witness_has_length(&transition, 1));
        transition.output_remainders.clear();
        assert!(!transition_witness_has_length(&transition, 1));
    }
}
