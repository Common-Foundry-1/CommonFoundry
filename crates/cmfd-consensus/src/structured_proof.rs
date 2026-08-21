//! Fail-closed aggregate verifier boundary for the ForgeMatrix proof research.
//!
//! The matrix, transition, and successor-wiring arguments reduce the complete
//! computation to multilinear opening claims. This module binds those
//! components together, pins the fixed model commitments, parses one bounded
//! canonical envelope, and refuses to accept the result unless a caller-owned
//! PCS verifier authenticates every resulting opening.
//!
//! No production PCS or hash argument is selected here. Implementing
//! [`StructuredPcsVerifier`] or [`StructuredBlake3Verifier`] with a test stub
//! does not make this a consensus-ready succinct proof.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    forgematrix_v2::{
        PRODUCTION_V2_BANKS, PRODUCTION_V2_BATCH, PRODUCTION_V2_DIMENSION, PRODUCTION_V2_LAYERS,
        PRODUCTION_V2_LAYERS_PER_BANK, work_digest_from_roots,
    },
    model_bank::ModelPcsIdentity,
    structured_sumcheck::{
        ExtensionElement, ExtensionField, StructuredMatrixProof, StructuredMatrixStatement,
        StructuredSumcheckError, verify_structured_matrix_sumcheck,
    },
    structured_transition::{
        STRUCTURED_TRANSITION_INPUT_ORACLE, StructuredMaskPolynomial, StructuredTransitionError,
        StructuredTransitionProof, StructuredTransitionStatement,
        verify_structured_transition_sumcheck,
    },
    structured_wiring::{
        MAX_STRUCTURED_WIRING_BANKS, StructuredWiringError, StructuredWiringProof,
        StructuredWiringStatement, verify_structured_wiring_component_commitments,
        verify_structured_wiring_openings,
    },
};

pub const STRUCTURED_AGGREGATE_VERSION: u32 = 3;
pub const MAX_STRUCTURED_AGGREGATE_PROOF_BYTES: usize = 5 * 1024 * 1024;
pub const MAX_STRUCTURED_PCS_PROOF_BYTES: usize = 512 * 1024;
pub const MAX_STRUCTURED_BLAKE3_PROOF_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_STRUCTURED_FINAL_ACTIVATION_BYTES: usize = 512 * 1024;
pub const MAX_STRUCTURED_OPENING_CLAIMS: usize = 4096;
pub const MAX_STRUCTURED_OPENING_VARIABLES: usize = 64;

const PROOF_MAGIC: &[u8; 8] = b"CMFDSA03";
const PUBLIC_BINDING_DOMAIN: &str = "CMFD/FORGEMATRIX/STRUCTURED-PUBLIC/V3";
const PRODUCTION_BANKS: usize = PRODUCTION_V2_BANKS as usize;
const PRODUCTION_BATCH: usize = PRODUCTION_V2_BATCH as usize;
const PRODUCTION_DIMENSION: usize = PRODUCTION_V2_DIMENSION as usize;
const PRODUCTION_LAYERS_PER_BANK: usize = PRODUCTION_V2_LAYERS_PER_BANK as usize;
const _: () =
    assert!(PRODUCTION_V2_LAYERS as usize == PRODUCTION_BANKS * PRODUCTION_LAYERS_PER_BANK);
const _: () = assert!(MAX_STRUCTURED_WIRING_BANKS == PRODUCTION_BANKS);

/// Complete consensus frame limit that a production ForgeMatrix proof must fit.
pub const STRUCTURED_PRODUCTION_FRAME_BYTES: usize = crate::wire::MAX_PROOF_BYTES;
/// Current V2 frame bytes retained by the proposed production wrapper.
pub const STRUCTURED_PRODUCTION_V2_WRAPPER_BYTES: usize = 193;
/// Length prefix for the structured aggregate appended to that wrapper.
pub const STRUCTURED_PRODUCTION_AGGREGATE_LENGTH_BYTES: usize = std::mem::size_of::<u32>();
/// Canonical V3 aggregate envelope excluding its BLAKE3 and PCS payload bytes.
pub const STRUCTURED_PRODUCTION_COMPONENT_FLOOR_BYTES: usize = 73_274;
/// Fixed split-PCS metadata for one base, three weight, and one trace section.
pub const STRUCTURED_PRODUCTION_SPLIT_PCS_FIXED_BYTES: usize = 312;
/// Split-PCS metadata added for every trace table.
pub const STRUCTURED_PRODUCTION_SPLIT_PCS_TRACE_TABLE_BYTES: usize = std::mem::size_of::<u32>();
/// Current V3 maximum number of tables in one aggregate section.
pub const STRUCTURED_PRODUCTION_SPLIT_V3_MAX_TRACE_TABLES: usize = 256;
/// Bytes shared by the BLAKE3 argument and the complete split PCS payload.
pub const STRUCTURED_PRODUCTION_SHARED_ARGUMENT_BYTES: usize = STRUCTURED_PRODUCTION_FRAME_BYTES
    - STRUCTURED_PRODUCTION_V2_WRAPPER_BYTES
    - STRUCTURED_PRODUCTION_AGGREGATE_LENGTH_BYTES
    - STRUCTURED_PRODUCTION_COMPONENT_FLOOR_BYTES;

/// Candidate aggregate floor after removing the BLAKE3 proof length field.
pub const STRUCTURED_BATCHED_PRODUCTION_COMPONENT_FLOOR_BYTES: usize =
    STRUCTURED_PRODUCTION_COMPONENT_FLOOR_BYTES - std::mem::size_of::<u32>();
/// Split-PCS metadata for one fixed-model section and one trace section.
pub const STRUCTURED_BATCHED_PRODUCTION_SPLIT_PCS_FIXED_BYTES: usize = 132;
/// PCS bytes available to the one-fixed/one-trace commitment-derived proposal.
pub const STRUCTURED_BATCHED_PRODUCTION_PCS_BYTES: usize = STRUCTURED_PRODUCTION_FRAME_BYTES
    - STRUCTURED_PRODUCTION_V2_WRAPPER_BYTES
    - STRUCTURED_PRODUCTION_AGGREGATE_LENGTH_BYTES
    - STRUCTURED_BATCHED_PRODUCTION_COMPONENT_FLOOR_BYTES;
/// Optimistic largest joint-model native payload with one trace table and a
/// nonempty trace payload. Additional trace tables consume four bytes each.
pub const STRUCTURED_BATCHED_PRODUCTION_MODEL_NATIVE_BYTES: usize =
    STRUCTURED_BATCHED_PRODUCTION_PCS_BYTES
        - STRUCTURED_BATCHED_PRODUCTION_SPLIT_PCS_FIXED_BYTES
        - STRUCTURED_PRODUCTION_SPLIT_PCS_TRACE_TABLE_BYTES
        - 1;

/// Exact whole-frame accounting for the current V3 four-fixed-child proposal.
///
/// Native WHIR payloads are not independently entitled to the wire proof cap:
/// all four fixed-model sections, the trace section, split metadata, and the
/// BLAKE3 argument share [`STRUCTURED_PRODUCTION_SHARED_ARGUMENT_BYTES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StructuredSplitV3ProductionBudget {
    pub blake3_argument_bytes: usize,
    pub base_model_native_bytes: usize,
    pub weight_model_native_bytes: [usize; PRODUCTION_BANKS],
    pub trace_native_bytes: usize,
    pub trace_table_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StructuredProductionProofUsage {
    pub pcs_payload_bytes: usize,
    pub shared_argument_bytes: usize,
    pub complete_frame_bytes: usize,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum StructuredProductionBudgetError {
    #[error("production proof payloads must be nonempty")]
    EmptyPayload,
    #[error("production trace table count is not canonically encodable")]
    InvalidTraceTableCount,
    #[error("production proof byte accounting overflowed")]
    ArithmeticOverflow,
    #[error("production proof requires {actual} bytes, exceeding the {maximum}-byte frame")]
    ProofTooLarge { actual: usize, maximum: usize },
}

impl StructuredSplitV3ProductionBudget {
    pub fn usage(self) -> Result<StructuredProductionProofUsage, StructuredProductionBudgetError> {
        if self.blake3_argument_bytes == 0
            || self.base_model_native_bytes == 0
            || self.weight_model_native_bytes.contains(&0)
            || self.trace_native_bytes == 0
        {
            return Err(StructuredProductionBudgetError::EmptyPayload);
        }
        if self.trace_table_count == 0
            || self.trace_table_count > STRUCTURED_PRODUCTION_SPLIT_V3_MAX_TRACE_TABLES
        {
            return Err(StructuredProductionBudgetError::InvalidTraceTableCount);
        }
        let trace_metadata = self
            .trace_table_count
            .checked_mul(STRUCTURED_PRODUCTION_SPLIT_PCS_TRACE_TABLE_BYTES)
            .ok_or(StructuredProductionBudgetError::ArithmeticOverflow)?;
        let weight_bytes = self
            .weight_model_native_bytes
            .into_iter()
            .try_fold(0_usize, |total, bytes| total.checked_add(bytes))
            .ok_or(StructuredProductionBudgetError::ArithmeticOverflow)?;
        let pcs_payload_bytes = STRUCTURED_PRODUCTION_SPLIT_PCS_FIXED_BYTES
            .checked_add(trace_metadata)
            .and_then(|total| total.checked_add(self.base_model_native_bytes))
            .and_then(|total| total.checked_add(weight_bytes))
            .and_then(|total| total.checked_add(self.trace_native_bytes))
            .ok_or(StructuredProductionBudgetError::ArithmeticOverflow)?;
        let shared_argument_bytes = self
            .blake3_argument_bytes
            .checked_add(pcs_payload_bytes)
            .ok_or(StructuredProductionBudgetError::ArithmeticOverflow)?;
        let complete_frame_bytes = STRUCTURED_PRODUCTION_V2_WRAPPER_BYTES
            .checked_add(STRUCTURED_PRODUCTION_AGGREGATE_LENGTH_BYTES)
            .and_then(|total| total.checked_add(STRUCTURED_PRODUCTION_COMPONENT_FLOOR_BYTES))
            .and_then(|total| total.checked_add(shared_argument_bytes))
            .ok_or(StructuredProductionBudgetError::ArithmeticOverflow)?;
        Ok(StructuredProductionProofUsage {
            pcs_payload_bytes,
            shared_argument_bytes,
            complete_frame_bytes,
        })
    }

    pub fn ensure_fits(
        self,
    ) -> Result<StructuredProductionProofUsage, StructuredProductionBudgetError> {
        let usage = self.usage()?;
        if usage.complete_frame_bytes > STRUCTURED_PRODUCTION_FRAME_BYTES {
            return Err(StructuredProductionBudgetError::ProofTooLarge {
                actual: usage.complete_frame_bytes,
                maximum: STRUCTURED_PRODUCTION_FRAME_BYTES,
            });
        }
        Ok(usage)
    }
}

/// Exact whole-frame estimator for the commitment-derived proposal with one
/// n33 fixed-model child and one joint trace child.
///
/// This describes a candidate format, not a deployed wire tag. It removes the
/// obsolete BLAKE3 proof blob and retains a same-size V2-derived outer wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StructuredBatchedProductionBudget {
    pub fixed_model_native_bytes: usize,
    pub trace_native_bytes: usize,
    pub trace_table_count: usize,
}

impl StructuredBatchedProductionBudget {
    pub fn usage(self) -> Result<StructuredProductionProofUsage, StructuredProductionBudgetError> {
        if self.fixed_model_native_bytes == 0 || self.trace_native_bytes == 0 {
            return Err(StructuredProductionBudgetError::EmptyPayload);
        }
        if self.trace_table_count == 0
            || self.trace_table_count > STRUCTURED_PRODUCTION_SPLIT_V3_MAX_TRACE_TABLES
        {
            return Err(StructuredProductionBudgetError::InvalidTraceTableCount);
        }
        let trace_metadata = self
            .trace_table_count
            .checked_mul(STRUCTURED_PRODUCTION_SPLIT_PCS_TRACE_TABLE_BYTES)
            .ok_or(StructuredProductionBudgetError::ArithmeticOverflow)?;
        let pcs_payload_bytes = STRUCTURED_BATCHED_PRODUCTION_SPLIT_PCS_FIXED_BYTES
            .checked_add(trace_metadata)
            .and_then(|total| total.checked_add(self.fixed_model_native_bytes))
            .and_then(|total| total.checked_add(self.trace_native_bytes))
            .ok_or(StructuredProductionBudgetError::ArithmeticOverflow)?;
        let complete_frame_bytes = STRUCTURED_PRODUCTION_V2_WRAPPER_BYTES
            .checked_add(STRUCTURED_PRODUCTION_AGGREGATE_LENGTH_BYTES)
            .and_then(|total| {
                total.checked_add(STRUCTURED_BATCHED_PRODUCTION_COMPONENT_FLOOR_BYTES)
            })
            .and_then(|total| total.checked_add(pcs_payload_bytes))
            .ok_or(StructuredProductionBudgetError::ArithmeticOverflow)?;
        Ok(StructuredProductionProofUsage {
            pcs_payload_bytes,
            shared_argument_bytes: pcs_payload_bytes,
            complete_frame_bytes,
        })
    }

    pub fn ensure_fits(
        self,
    ) -> Result<StructuredProductionProofUsage, StructuredProductionBudgetError> {
        let usage = self.usage()?;
        if usage.complete_frame_bytes > STRUCTURED_PRODUCTION_FRAME_BYTES {
            return Err(StructuredProductionBudgetError::ProofTooLarge {
                actual: usage.complete_frame_bytes,
                maximum: STRUCTURED_PRODUCTION_FRAME_BYTES,
            });
        }
        Ok(usage)
    }
}

/// Public data that fixes every component interpretation and fixed model
/// commitment in one ForgeMatrix execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredForgeMatrixStatement {
    pub challenge_digest: [u8; 32],
    pub public_binding: [u8; 32],
    pub model_byte_root: [u8; 32],
    pub model_pcs_root: [u8; 32],
    pub final_activation_digest: [u8; 32],
    pub work_digest: [u8; 32],
    pub work_target: [u8; 32],
    pub base_input_commitment: [u8; 32],
    pub weight_commitments: Vec<[u8; 32]>,
    pub final_bank_output_commitment: [u8; 32],
    pub initialization_statement: StructuredTransitionStatement,
    pub initialization_mask: StructuredMaskPolynomial,
    pub matrix_statements: Vec<StructuredMatrixStatement>,
    pub transition_statements: Vec<StructuredTransitionStatement>,
    pub transition_masks: Vec<StructuredMaskPolynomial>,
    pub wiring_statement: StructuredWiringStatement,
}

/// Exact component shape of the proposed production research aggregate.
///
/// This only admits verifier-side statement validation. It does not select a
/// production proof tag or make the materializing research provers capable of
/// constructing these tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StructuredForgeMatrixResearchShape {
    pub initialization_statement: StructuredTransitionStatement,
    pub matrix_statements: [StructuredMatrixStatement; PRODUCTION_BANKS],
    pub transition_statements: [StructuredTransitionStatement; PRODUCTION_BANKS],
    pub wiring_statement: StructuredWiringStatement,
}

impl StructuredForgeMatrixResearchShape {
    pub const fn production_candidate() -> Self {
        let matrix = StructuredMatrixStatement {
            layers: PRODUCTION_LAYERS_PER_BANK,
            rows: PRODUCTION_BATCH,
            inner: PRODUCTION_DIMENSION,
            cols: PRODUCTION_DIMENSION,
            max_abs_activation: 125,
            max_abs_weight: 125,
            max_abs_accumulator: 64_000_000,
        };
        let transition = StructuredTransitionStatement {
            layers: PRODUCTION_LAYERS_PER_BANK,
            rows: PRODUCTION_BATCH,
            cols: PRODUCTION_DIMENSION,
            max_abs_accumulator: 64_000_000,
            max_mask: 5_000,
        };
        Self {
            initialization_statement: StructuredTransitionStatement {
                layers: 1,
                rows: PRODUCTION_BATCH,
                cols: PRODUCTION_DIMENSION,
                max_abs_accumulator: 125,
                max_mask: 5_000,
            },
            matrix_statements: [matrix; PRODUCTION_BANKS],
            transition_statements: [transition; PRODUCTION_BANKS],
            wiring_statement: StructuredWiringStatement {
                banks: PRODUCTION_BANKS,
                layers_per_bank: PRODUCTION_LAYERS_PER_BANK,
                rows: PRODUCTION_BATCH,
                cols: PRODUCTION_DIMENSION,
                max_abs_activation: 125,
            },
        }
    }

    pub fn validate_verifier_shape(&self) -> Result<(), StructuredProofError> {
        self.initialization_statement.validate_verifier_shape()?;
        for statement in &self.matrix_statements {
            statement.validate_verifier_shape()?;
        }
        for statement in &self.transition_statements {
            statement.validate_verifier_shape()?;
        }
        self.wiring_statement.validate_verifier_shape()?;
        if *self != Self::production_candidate() {
            return Err(StructuredProofError::ComponentShape);
        }
        Ok(())
    }

    pub fn validate_materialized_shape(&self) -> Result<(), StructuredProofError> {
        self.validate_verifier_shape()?;
        self.initialization_statement
            .validate_materialized_shape()?;
        for statement in &self.matrix_statements {
            statement.validate_materialized_shape()?;
        }
        for statement in &self.transition_statements {
            statement.validate_materialized_shape()?;
        }
        self.wiring_statement.validate_materialized_shape()?;
        Ok(())
    }
}

/// Canonical aggregate research envelope. The opaque hash and PCS proofs are
/// accepted only through the verifiers supplied to
/// [`verify_structured_forgematrix_proof`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredForgeMatrixProof {
    pub protocol_version: u32,
    pub initialization_proof: StructuredTransitionProof,
    pub matrix_proofs: Vec<StructuredMatrixProof>,
    pub transition_proofs: Vec<StructuredTransitionProof>,
    pub wiring_proof: StructuredWiringProof,
    /// Succinct argument that the private final activation hashes to the
    /// statement digest and has the authenticated last-layer MLE opening.
    pub blake3_proof: Vec<u8>,
    pub pcs_proof: Vec<u8>,
}

/// Public statement for the final-output BLAKE3 subargument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredBlake3Statement {
    pub challenge_digest: [u8; 32],
    pub final_activation_len: usize,
    pub final_activation_digest: [u8; 32],
    pub final_activation_point: Vec<ExtensionElement>,
    pub final_activation_evaluation: ExtensionElement,
}

/// One explicit multilinear opening which the selected PCS must authenticate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredPcsOpeningClaim {
    pub commitment: [u8; 32],
    pub point: Vec<ExtensionElement>,
    pub evaluation: ExtensionElement,
}

/// Semantically separated PCS openings for the immutable model and the
/// challenge-specific execution trace.
///
/// Keeping these scopes distinct prevents a trace proof from silently
/// substituting commitments for the model identity pinned by consensus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredPcsOpeningSet {
    pub fixed_model: Vec<StructuredPcsOpeningClaim>,
    pub trace: Vec<StructuredPcsOpeningClaim>,
}

/// Consensus-owned PCS verifier boundary.
///
/// Implementations must bind `public_binding`, the trusted model identity,
/// both opening scopes, and `proof` in one pinned transcript. They must be
/// deterministic, panic-free for untrusted bytes, and reject noncanonical
/// encodings before this interface is eligible for consensus use.
pub trait StructuredPcsVerifier: Send + Sync {
    fn verify_openings(
        &self,
        public_binding: &[u8; 32],
        trusted_model: &ModelPcsIdentity,
        openings: &StructuredPcsOpeningSet,
        proof: &[u8],
    ) -> bool;
}

/// Consensus-owned verifier boundary for the final-output hash argument.
pub trait StructuredBlake3Verifier: Send + Sync {
    fn verify_argument(&self, statement: &StructuredBlake3Statement, proof: &[u8]) -> bool;
}

/// Derives the transcript binding that commits the algebraic proof challenges
/// to the exact mining challenge, model identities, final digest, work digest,
/// target, and final-table length before any random opening point is sampled.
#[allow(clippy::too_many_arguments)]
pub fn structured_forgematrix_public_binding(
    challenge_digest: [u8; 32],
    model_byte_root: [u8; 32],
    model_pcs_identity: &ModelPcsIdentity,
    final_activation_digest: [u8; 32],
    work_digest: [u8; 32],
    work_target: [u8; 32],
    final_activation_len: usize,
) -> Result<[u8; 32], StructuredProofError> {
    let final_activation_len = u64::try_from(final_activation_len)
        .map_err(|_| StructuredProofError::FinalActivationShape)?;
    let model_pcs_identity_digest = model_pcs_identity
        .digest()
        .map_err(|_| StructuredProofError::InvalidModelPcsIdentity)?;
    let mut hasher = blake3::Hasher::new_derive_key(PUBLIC_BINDING_DOMAIN);
    hasher.update(&STRUCTURED_AGGREGATE_VERSION.to_le_bytes());
    hasher.update(&challenge_digest);
    hasher.update(&model_byte_root);
    hasher.update(&model_pcs_identity_digest);
    hasher.update(&final_activation_digest);
    hasher.update(&work_digest);
    hasher.update(&work_target);
    hasher.update(&final_activation_len.to_le_bytes());
    Ok(*hasher.finalize().as_bytes())
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StructuredProofError {
    #[error("aggregate proof protocol version mismatch")]
    ProtocolVersion,
    #[error("aggregate statement component counts do not match")]
    ComponentCount,
    #[error("aggregate statement component dimensions or bounds do not match")]
    ComponentShape,
    #[error("matrix proof does not use the pinned model weight commitment")]
    WeightCommitment,
    #[error("wiring proof does not bind the declared final-bank output commitment")]
    FinalBankOutputCommitment,
    #[error("aggregate public binding does not match its challenge, model, digest, and target")]
    PublicBinding,
    #[error("final activation has the wrong shape")]
    FinalActivationShape,
    #[error("final activation does not match the authenticated final output opening")]
    FinalActivationOpening,
    #[error("aggregate proof is missing its BLAKE3 argument")]
    MissingBlake3Proof,
    #[error("the selected BLAKE3 argument verifier rejected the final-output hash proof")]
    Blake3Rejected,
    #[error("work digest mismatch")]
    WorkDigest,
    #[error("work digest does not meet the block target")]
    HighHash,
    #[error("model digest roots are not committed")]
    ModelBinding,
    #[error("trusted model PCS identity is malformed")]
    InvalidModelPcsIdentity,
    #[error("aggregate statement does not exactly match the trusted model PCS identity")]
    ModelPcsIdentityMismatch,
    #[error("aggregate proof is missing its authenticated PCS opening proof")]
    MissingPcsProof,
    #[error("aggregate proof contains too many PCS opening claims")]
    OpeningCount,
    #[error("aggregate proof opening point exceeds the variable cap")]
    OpeningVariables,
    #[error("the same PCS commitment and point claim conflicting evaluations")]
    ConflictingOpening,
    #[error("the same PCS commitment appears in fixed-model and trace opening scopes")]
    OpeningScopeConflict,
    #[error("the selected PCS rejected one or more aggregate opening claims")]
    PcsRejected,
    #[error("aggregate proof exceeds its research byte cap")]
    ProofTooLarge,
    #[error("aggregate proof is truncated, malformed, or has trailing bytes")]
    Decode,
    #[error("matrix component failed: {0}")]
    Matrix(#[from] StructuredSumcheckError),
    #[error("transition component failed: {0}")]
    Transition(#[from] StructuredTransitionError),
    #[error("wiring component failed: {0}")]
    Wiring(#[from] StructuredWiringError),
}

impl StructuredForgeMatrixProof {
    pub fn encode(&self) -> Result<Vec<u8>, StructuredProofError> {
        if self.matrix_proofs.len() > MAX_STRUCTURED_WIRING_BANKS
            || self.transition_proofs.len() > MAX_STRUCTURED_WIRING_BANKS
        {
            return Err(StructuredProofError::ComponentCount);
        }
        if self.pcs_proof.is_empty() {
            return Err(StructuredProofError::MissingPcsProof);
        }
        if self.pcs_proof.len() > MAX_STRUCTURED_PCS_PROOF_BYTES {
            return Err(StructuredProofError::ProofTooLarge);
        }
        if self.blake3_proof.is_empty() {
            return Err(StructuredProofError::MissingBlake3Proof);
        }
        if self.blake3_proof.len() > MAX_STRUCTURED_BLAKE3_PROOF_BYTES {
            return Err(StructuredProofError::ProofTooLarge);
        }

        let initialization = self.initialization_proof.encode()?;
        let matrices = self
            .matrix_proofs
            .iter()
            .map(StructuredMatrixProof::encode)
            .collect::<Result<Vec<_>, _>>()?;
        let transitions = self
            .transition_proofs
            .iter()
            .map(StructuredTransitionProof::encode)
            .collect::<Result<Vec<_>, _>>()?;
        let wiring = self.wiring_proof.encode()?;

        let mut output = Vec::new();
        output.extend_from_slice(PROOF_MAGIC);
        output.extend_from_slice(&self.protocol_version.to_le_bytes());
        encode_blob(&mut output, &initialization)?;
        encode_blobs(&mut output, &matrices)?;
        encode_blobs(&mut output, &transitions)?;
        encode_blob(&mut output, &wiring)?;
        encode_blob(&mut output, &self.blake3_proof)?;
        encode_blob(&mut output, &self.pcs_proof)?;
        if output.len() > MAX_STRUCTURED_AGGREGATE_PROOF_BYTES {
            return Err(StructuredProofError::ProofTooLarge);
        }
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StructuredProofError> {
        if bytes.len() > MAX_STRUCTURED_AGGREGATE_PROOF_BYTES {
            return Err(StructuredProofError::ProofTooLarge);
        }
        let mut reader = ProofReader::new(bytes);
        if reader.take(PROOF_MAGIC.len())? != PROOF_MAGIC {
            return Err(StructuredProofError::Decode);
        }
        let protocol_version = reader.u32()?;
        let initialization_proof = StructuredTransitionProof::decode(
            reader.blob(crate::MAX_STRUCTURED_TRANSITION_PROOF_BYTES)?,
        )?;
        let matrix_count = reader.count(MAX_STRUCTURED_WIRING_BANKS)?;
        let mut matrix_proofs = Vec::with_capacity(matrix_count);
        for _ in 0..matrix_count {
            matrix_proofs.push(StructuredMatrixProof::decode(
                reader.blob(crate::MAX_STRUCTURED_SUMCHECK_PROOF_BYTES)?,
            )?);
        }
        let transition_count = reader.count(MAX_STRUCTURED_WIRING_BANKS)?;
        let mut transition_proofs = Vec::with_capacity(transition_count);
        for _ in 0..transition_count {
            transition_proofs.push(StructuredTransitionProof::decode(
                reader.blob(crate::MAX_STRUCTURED_TRANSITION_PROOF_BYTES)?,
            )?);
        }
        let wiring_proof =
            StructuredWiringProof::decode(reader.blob(crate::MAX_STRUCTURED_WIRING_PROOF_BYTES)?)?;
        let blake3_proof = reader.blob(MAX_STRUCTURED_BLAKE3_PROOF_BYTES)?.to_vec();
        if blake3_proof.is_empty() {
            return Err(StructuredProofError::MissingBlake3Proof);
        }
        let pcs_proof = reader.blob(MAX_STRUCTURED_PCS_PROOF_BYTES)?.to_vec();
        if pcs_proof.is_empty() {
            return Err(StructuredProofError::MissingPcsProof);
        }
        if !reader.is_empty() {
            return Err(StructuredProofError::Decode);
        }
        Ok(Self {
            protocol_version,
            initialization_proof,
            matrix_proofs,
            transition_proofs,
            wiring_proof,
            blake3_proof,
            pcs_proof,
        })
    }
}

/// Verifies all algebraic component transcripts and commitment identities,
/// then requires the selected PCS to authenticate every terminal opening.
pub fn verify_structured_forgematrix_proof(
    statement: &StructuredForgeMatrixStatement,
    proof: &StructuredForgeMatrixProof,
    trusted_model: &ModelPcsIdentity,
    pcs: &dyn StructuredPcsVerifier,
    blake3: &dyn StructuredBlake3Verifier,
) -> Result<(), StructuredProofError> {
    validate_model_pcs_identity(statement, trusted_model)?;
    if proof.pcs_proof.is_empty() {
        return Err(StructuredProofError::MissingPcsProof);
    }
    // Enforce all in-memory resource and canonical-field checks as well as the
    // byte parser does for an untrusted wire proof.
    proof.encode()?;
    let openings = collect_structured_forgematrix_openings(statement, proof, trusted_model)?;
    let hash_statement = structured_blake3_statement(statement, proof, trusted_model)?;
    if !blake3.verify_argument(&hash_statement, &proof.blake3_proof) {
        return Err(StructuredProofError::Blake3Rejected);
    }
    if !pcs.verify_openings(
        &statement.public_binding,
        trusted_model,
        &openings,
        &proof.pcs_proof,
    ) {
        return Err(StructuredProofError::PcsRejected);
    }
    Ok(())
}

/// Checks every algebraic component and commitment link, returning the exact
/// terminal claims that an aggregate PCS must authenticate.
///
/// This is the prover/verifier seam used by experimental PCS backends. It does
/// not accept a ForgeMatrix proof by itself.
pub fn collect_structured_forgematrix_openings(
    statement: &StructuredForgeMatrixStatement,
    proof: &StructuredForgeMatrixProof,
    trusted_model: &ModelPcsIdentity,
) -> Result<StructuredPcsOpeningSet, StructuredProofError> {
    validate_model_pcs_identity(statement, trusted_model)?;
    validate_component_shapes(statement, proof)?;
    if proof.protocol_version != STRUCTURED_AGGREGATE_VERSION {
        return Err(StructuredProofError::ProtocolVersion);
    }
    validate_final_output_metadata(statement, proof, trusted_model)?;

    verify_structured_wiring_component_commitments(
        statement.wiring_statement,
        statement.base_input_commitment,
        &proof.initialization_proof,
        &proof.matrix_proofs,
        &proof.transition_proofs,
        &proof.wiring_proof,
    )?;
    for (matrix, expected_weight) in proof
        .matrix_proofs
        .iter()
        .zip(&statement.weight_commitments)
    {
        if matrix.weight_commitment != *expected_weight {
            return Err(StructuredProofError::WeightCommitment);
        }
    }
    if proof.wiring_proof.output_commitments.last() != Some(&statement.final_bank_output_commitment)
    {
        return Err(StructuredProofError::FinalBankOutputCommitment);
    }

    let binding = &statement.public_binding;
    let initialization = verify_structured_transition_sumcheck(
        binding,
        statement.initialization_statement,
        &statement.initialization_mask,
        &proof.initialization_proof,
    )?;
    let mut initialization_openings = transition_openings(initialization)?;
    if initialization_openings.is_empty() {
        return Err(StructuredProofError::ComponentCount);
    }
    let mut fixed_model = vec![initialization_openings.remove(STRUCTURED_TRANSITION_INPUT_ORACLE)];
    let mut trace = initialization_openings;
    for ((matrix_statement, transition_statement), (transition_mask, (matrix, transition))) in
        statement
            .matrix_statements
            .iter()
            .zip(&statement.transition_statements)
            .zip(
                statement
                    .transition_masks
                    .iter()
                    .zip(proof.matrix_proofs.iter().zip(&proof.transition_proofs)),
            )
    {
        let matrix_claims = verify_structured_matrix_sumcheck(binding, *matrix_statement, matrix)?;
        trace.push(StructuredPcsOpeningClaim {
            commitment: matrix_claims.activation_commitment,
            point: matrix_claims.activation_point,
            evaluation: matrix_claims.activation_evaluation,
        });
        fixed_model.push(StructuredPcsOpeningClaim {
            commitment: matrix_claims.weight_commitment,
            point: matrix_claims.weight_point,
            evaluation: matrix_claims.weight_evaluation,
        });
        trace.push(StructuredPcsOpeningClaim {
            commitment: matrix_claims.accumulator_commitment,
            point: matrix_claims.accumulator_point,
            evaluation: matrix_claims.accumulator_evaluation,
        });
        let transition_claims = verify_structured_transition_sumcheck(
            binding,
            *transition_statement,
            transition_mask,
            transition,
        )?;
        trace.extend(transition_openings(transition_claims)?);
    }
    let wiring = verify_structured_wiring_openings(
        binding,
        statement.wiring_statement,
        &proof.wiring_proof,
    )?;
    validate_final_output_opening(statement, &wiring.final_output)?;
    trace.extend(
        wiring
            .openings
            .into_iter()
            .map(|claim| StructuredPcsOpeningClaim {
                commitment: claim.commitment,
                point: claim.point,
                evaluation: claim.evaluation,
            }),
    );

    canonical_opening_set(fixed_model, trace)
}

fn validate_model_pcs_identity(
    statement: &StructuredForgeMatrixStatement,
    trusted_model: &ModelPcsIdentity,
) -> Result<(), StructuredProofError> {
    trusted_model
        .validate()
        .map_err(|_| StructuredProofError::InvalidModelPcsIdentity)?;
    let commitment_root = trusted_model
        .commitment_root()
        .map_err(|_| StructuredProofError::InvalidModelPcsIdentity)?;
    let wiring = statement.wiring_statement;
    if statement.model_byte_root != trusted_model.model_byte_root
        || statement.model_pcs_root != commitment_root
        || statement.base_input_commitment != trusted_model.base_input_commitment
        || statement.weight_commitments != trusted_model.weight_bank_commitments
        || wiring.banks != trusted_model.weight_bank_commitments.len()
        || u32::try_from(wiring.rows).ok() != Some(trusted_model.batch)
        || u32::try_from(wiring.cols).ok() != Some(trusted_model.dimension)
        || u32::try_from(wiring.layers_per_bank).ok() != Some(trusted_model.layers_per_bank)
    {
        return Err(StructuredProofError::ModelPcsIdentityMismatch);
    }
    Ok(())
}

fn validate_final_output_metadata(
    statement: &StructuredForgeMatrixStatement,
    proof: &StructuredForgeMatrixProof,
    trusted_model: &ModelPcsIdentity,
) -> Result<(), StructuredProofError> {
    if proof.blake3_proof.is_empty() {
        return Err(StructuredProofError::MissingBlake3Proof);
    }
    let expected_len = statement
        .wiring_statement
        .rows
        .checked_mul(statement.wiring_statement.cols)
        .ok_or(StructuredProofError::FinalActivationShape)?;
    if expected_len == 0 || expected_len > MAX_STRUCTURED_FINAL_ACTIVATION_BYTES {
        return Err(StructuredProofError::FinalActivationShape);
    }
    if statement.model_byte_root == [0; 32] || statement.model_pcs_root == [0; 32] {
        return Err(StructuredProofError::ModelBinding);
    }
    let expected_work_digest = work_digest_from_roots(
        statement.challenge_digest,
        statement.model_byte_root,
        statement.model_pcs_root,
        statement.final_activation_digest,
    );
    if statement.work_digest != expected_work_digest {
        return Err(StructuredProofError::WorkDigest);
    }
    if statement.work_digest > statement.work_target {
        return Err(StructuredProofError::HighHash);
    }
    let expected_binding = structured_forgematrix_public_binding(
        statement.challenge_digest,
        statement.model_byte_root,
        trusted_model,
        statement.final_activation_digest,
        statement.work_digest,
        statement.work_target,
        expected_len,
    )?;
    if statement.public_binding != expected_binding {
        return Err(StructuredProofError::PublicBinding);
    }
    Ok(())
}

fn validate_final_output_opening(
    statement: &StructuredForgeMatrixStatement,
    final_output: &crate::StructuredWiringOpeningClaim,
) -> Result<(), StructuredProofError> {
    let wiring = statement.wiring_statement;
    let cell_variables = wiring.cols.ilog2() as usize + wiring.rows.ilog2() as usize;
    let layer_variables = wiring.layers_per_bank.ilog2() as usize;
    if final_output.commitment != statement.final_bank_output_commitment
        || final_output.point.len() != cell_variables + layer_variables
        || final_output.point[cell_variables..]
            .iter()
            .any(|coordinate| *coordinate != ExtensionElement::from_field(ExtensionField::ONE))
    {
        return Err(StructuredProofError::FinalActivationOpening);
    }
    Ok(())
}

fn structured_blake3_statement(
    statement: &StructuredForgeMatrixStatement,
    proof: &StructuredForgeMatrixProof,
    trusted_model: &ModelPcsIdentity,
) -> Result<StructuredBlake3Statement, StructuredProofError> {
    validate_final_output_metadata(statement, proof, trusted_model)?;
    let wiring = verify_structured_wiring_openings(
        &statement.public_binding,
        statement.wiring_statement,
        &proof.wiring_proof,
    )?;
    validate_final_output_opening(statement, &wiring.final_output)?;
    let cell_variables = statement.wiring_statement.cols.ilog2() as usize
        + statement.wiring_statement.rows.ilog2() as usize;
    Ok(StructuredBlake3Statement {
        challenge_digest: statement.challenge_digest,
        final_activation_len: statement.wiring_statement.rows * statement.wiring_statement.cols,
        final_activation_digest: statement.final_activation_digest,
        final_activation_point: wiring.final_output.point[..cell_variables].to_vec(),
        final_activation_evaluation: wiring.final_output.evaluation,
    })
}

fn validate_component_shapes(
    statement: &StructuredForgeMatrixStatement,
    proof: &StructuredForgeMatrixProof,
) -> Result<(), StructuredProofError> {
    let banks = statement.wiring_statement.banks;
    if banks == 0
        || banks > MAX_STRUCTURED_WIRING_BANKS
        || statement.weight_commitments.len() != banks
        || statement.matrix_statements.len() != banks
        || statement.transition_statements.len() != banks
        || statement.transition_masks.len() != banks
        || proof.matrix_proofs.len() != banks
        || proof.transition_proofs.len() != banks
    {
        return Err(StructuredProofError::ComponentCount);
    }
    let wiring = statement.wiring_statement;
    let initialization = statement.initialization_statement;
    if initialization.layers != 1
        || initialization.rows != wiring.rows
        || initialization.cols != wiring.cols
        || initialization.max_abs_accumulator != wiring.max_abs_activation
    {
        return Err(StructuredProofError::ComponentShape);
    }
    for (matrix, transition) in statement
        .matrix_statements
        .iter()
        .zip(&statement.transition_statements)
    {
        if matrix.layers != wiring.layers_per_bank
            || matrix.rows != wiring.rows
            || matrix.inner != wiring.cols
            || matrix.cols != wiring.cols
            || matrix.max_abs_activation != wiring.max_abs_activation
            || transition.layers != wiring.layers_per_bank
            || transition.rows != wiring.rows
            || transition.cols != wiring.cols
            || transition.max_abs_accumulator != matrix.max_abs_accumulator
        {
            return Err(StructuredProofError::ComponentShape);
        }
    }
    Ok(())
}

fn transition_openings(
    claims: crate::StructuredTransitionOpeningClaims,
) -> Result<Vec<StructuredPcsOpeningClaim>, StructuredProofError> {
    if claims.oracle_commitments.is_empty()
        || claims.oracle_commitments.len() != claims.evaluations.len()
    {
        return Err(StructuredProofError::ComponentCount);
    }
    Ok(claims
        .oracle_commitments
        .into_iter()
        .zip(claims.evaluations)
        .map(|(commitment, evaluation)| StructuredPcsOpeningClaim {
            commitment,
            point: claims.point.clone(),
            evaluation,
        })
        .collect())
}

fn canonical_opening_set(
    fixed_model: Vec<StructuredPcsOpeningClaim>,
    trace: Vec<StructuredPcsOpeningClaim>,
) -> Result<StructuredPcsOpeningSet, StructuredProofError> {
    if fixed_model
        .len()
        .checked_add(trace.len())
        .is_none_or(|count| count > MAX_STRUCTURED_OPENING_CLAIMS)
    {
        return Err(StructuredProofError::OpeningCount);
    }
    let fixed_model = canonical_openings(fixed_model)?;
    let trace = canonical_openings(trace)?;
    let fixed_commitments = fixed_model
        .iter()
        .map(|claim| claim.commitment)
        .collect::<BTreeSet<_>>();
    if trace
        .iter()
        .any(|claim| fixed_commitments.contains(&claim.commitment))
    {
        return Err(StructuredProofError::OpeningScopeConflict);
    }
    Ok(StructuredPcsOpeningSet { fixed_model, trace })
}

pub(crate) fn canonical_openings(
    openings: Vec<StructuredPcsOpeningClaim>,
) -> Result<Vec<StructuredPcsOpeningClaim>, StructuredProofError> {
    if openings.len() > MAX_STRUCTURED_OPENING_CLAIMS {
        return Err(StructuredProofError::OpeningCount);
    }
    let mut unique = BTreeMap::<Vec<u8>, StructuredPcsOpeningClaim>::new();
    for opening in openings {
        if opening.point.len() > MAX_STRUCTURED_OPENING_VARIABLES {
            return Err(StructuredProofError::OpeningVariables);
        }
        opening.evaluation.to_field()?;
        let mut key = Vec::with_capacity(36 + opening.point.len() * 24);
        key.extend_from_slice(&opening.commitment);
        key.extend_from_slice(&(opening.point.len() as u32).to_le_bytes());
        for coordinate in &opening.point {
            coordinate.to_field()?;
            coordinate.encode(&mut key);
        }
        match unique.get(&key) {
            Some(existing) if existing.evaluation != opening.evaluation => {
                return Err(StructuredProofError::ConflictingOpening);
            }
            Some(_) => {}
            None => {
                unique.insert(key, opening);
            }
        }
    }
    Ok(unique.into_values().collect())
}

fn encode_blobs(output: &mut Vec<u8>, values: &[Vec<u8>]) -> Result<(), StructuredProofError> {
    let count = u32::try_from(values.len()).map_err(|_| StructuredProofError::ProofTooLarge)?;
    output.extend_from_slice(&count.to_le_bytes());
    for value in values {
        encode_blob(output, value)?;
    }
    Ok(())
}

fn encode_blob(output: &mut Vec<u8>, value: &[u8]) -> Result<(), StructuredProofError> {
    let length = u32::try_from(value.len()).map_err(|_| StructuredProofError::ProofTooLarge)?;
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(value);
    Ok(())
}

struct ProofReader<'a> {
    remaining: &'a [u8],
}

impl<'a> ProofReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], StructuredProofError> {
        if self.remaining.len() < length {
            return Err(StructuredProofError::Decode);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32, StructuredProofError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes(
            bytes.try_into().map_err(|_| StructuredProofError::Decode)?,
        ))
    }

    fn count(&mut self, maximum: usize) -> Result<usize, StructuredProofError> {
        let count = self.u32()? as usize;
        if count > maximum {
            return Err(StructuredProofError::ComponentCount);
        }
        Ok(count)
    }

    fn blob(&mut self, maximum: usize) -> Result<&'a [u8], StructuredProofError> {
        let length = self.u32()? as usize;
        if length > maximum {
            return Err(StructuredProofError::ProofTooLarge);
        }
        self.take(length)
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    #[cfg(feature = "whir-prototype")]
    use crate::whir_proof::{StructuredWhirModelCommitmentSet, StructuredWhirModelMetadata};
    use crate::{
        BlockChallenge, ReductionWitness, StructuredTransitionWitness,
        prove_structured_matrix_product, prove_structured_transition, prove_structured_wiring,
        structured_sumcheck::ExtensionField, structured_sumcheck::table_commitment,
        v2_test_reference,
    };
    #[cfg(feature = "whir-prototype")]
    use crate::{
        StructuredWhirCommitmentSet, StructuredWhirPcsVerifier,
        prove_structured_matrix_product_with_commitments,
        prove_structured_transition_with_commitments, prove_structured_whir_openings,
        prove_structured_wiring_with_commitments, structured_matrix_whir_tables,
        structured_transition_whir_tables, structured_wiring_whir_tables,
        verify_structured_whir_openings,
    };

    struct TestPcs {
        accept: bool,
    }

    struct TestBlake3 {
        accept: bool,
    }

    struct ForwardingPcs {
        expected_identity: ModelPcsIdentity,
        called: AtomicBool,
    }

    struct NeverPcs;

    impl StructuredPcsVerifier for TestPcs {
        fn verify_openings(
            &self,
            _public_binding: &[u8; 32],
            trusted_model: &ModelPcsIdentity,
            openings: &StructuredPcsOpeningSet,
            proof: &[u8],
        ) -> bool {
            self.accept
                && trusted_model.validate().is_ok()
                && !openings.fixed_model.is_empty()
                && !openings.trace.is_empty()
                && proof == b"authenticated-openings"
        }
    }

    impl StructuredPcsVerifier for ForwardingPcs {
        fn verify_openings(
            &self,
            _public_binding: &[u8; 32],
            trusted_model: &ModelPcsIdentity,
            openings: &StructuredPcsOpeningSet,
            proof: &[u8],
        ) -> bool {
            self.called.store(true, Ordering::SeqCst);
            let fixed_commitments = openings
                .fixed_model
                .iter()
                .map(|claim| claim.commitment)
                .collect::<BTreeSet<_>>();
            let expected_commitments = std::iter::once(trusted_model.base_input_commitment)
                .chain(trusted_model.weight_bank_commitments.iter().copied())
                .collect::<BTreeSet<_>>();
            trusted_model == &self.expected_identity
                && fixed_commitments == expected_commitments
                && !openings.trace.is_empty()
                && proof == b"authenticated-openings"
        }
    }

    impl StructuredPcsVerifier for NeverPcs {
        fn verify_openings(
            &self,
            _public_binding: &[u8; 32],
            _trusted_model: &ModelPcsIdentity,
            _openings: &StructuredPcsOpeningSet,
            _proof: &[u8],
        ) -> bool {
            panic!("PCS verifier must not run before trusted model validation")
        }
    }

    impl StructuredBlake3Verifier for TestBlake3 {
        fn verify_argument(&self, statement: &StructuredBlake3Statement, proof: &[u8]) -> bool {
            self.accept
                && statement.final_activation_len != 0
                && !statement.final_activation_point.is_empty()
                && proof == b"authenticated-blake3"
        }
    }

    fn append_reduction(
        witness: &mut StructuredTransitionWitness,
        accumulator: i64,
        reduction: &ReductionWitness,
        activation: i64,
    ) {
        witness.accumulators.push(accumulator);
        witness
            .masks
            .push(u64::try_from(i64::from(reduction.z) - accumulator).unwrap());
        witness.encoded.push(u64::from(reduction.encoded_z));
        witness
            .square_quotients
            .push(u64::from(reduction.square_quotient));
        witness
            .square_remainders
            .push(u64::from(reduction.square_remainder));
        witness
            .cube_quotients
            .push(u64::from(reduction.cube_quotient));
        witness
            .cube_remainders
            .push(u64::from(reduction.cube_remainder));
        witness
            .output_quotients
            .push(u64::from(reduction.output_quotient));
        witness
            .output_remainders
            .push(u64::from(reduction.output_remainder));
        witness.negative.push(u64::from(reduction.z < 0));
        witness.activations.push(activation);
    }

    fn empty_witness() -> StructuredTransitionWitness {
        StructuredTransitionWitness {
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
        }
    }

    struct FixtureData {
        challenge_digest: [u8; 32],
        binding: [u8; 32],
        identity: ModelPcsIdentity,
        #[cfg(feature = "whir-prototype")]
        final_activation: Vec<u8>,
        final_activation_digest: [u8; 32],
        work_digest: [u8; 32],
        work_target: [u8; 32],
        initial: Vec<i64>,
        inputs: Vec<i64>,
        outputs: Vec<i64>,
        weights: Vec<i64>,
        accumulators: Vec<i64>,
        initialization_witness: StructuredTransitionWitness,
        transition_witness: StructuredTransitionWitness,
        initialization_statement: StructuredTransitionStatement,
        initialization_mask: StructuredMaskPolynomial,
        matrix_statement: StructuredMatrixStatement,
        transition_statement: StructuredTransitionStatement,
        transition_mask: StructuredMaskPolynomial,
        wiring_statement: StructuredWiringStatement,
    }

    fn fixture_data() -> FixtureData {
        let block = BlockChallenge {
            network_id: [0x63; 32],
            previous_block: [0x11; 32],
            transaction_root: [0x22; 32],
            height: 42,
            timestamp: 1_777_777_777,
            target: [0xff; 32],
        };
        let reference = v2_test_reference().unwrap();
        let trace = reference.prove_reference(&block, 7).unwrap();
        let model = reference.accelerator_model();
        let rows = model.rows() as usize;
        let cols = model.width() as usize;
        let layers = model.layers() as usize;
        let descriptor = reference.descriptor();
        let final_activation = trace
            .layers
            .last()
            .unwrap()
            .output
            .iter()
            .map(|value| u8::try_from(*value + 125).unwrap())
            .collect::<Vec<_>>();
        let initial = trace
            .initial_activation
            .iter()
            .map(|value| i64::from(*value))
            .collect::<Vec<_>>();
        let mut inputs = initial.clone();
        for layer in trace.layers.iter().take(layers - 1) {
            inputs.extend(layer.output.iter().map(|value| i64::from(*value)));
        }
        let outputs = trace
            .layers
            .iter()
            .flat_map(|layer| layer.output.iter().map(|value| i64::from(*value)))
            .collect::<Vec<_>>();
        let weights = model
            .weights()
            .iter()
            .map(|value| i64::from(*value) - 125)
            .collect::<Vec<_>>();
        let accumulators = trace
            .layers
            .iter()
            .flat_map(|layer| layer.accumulators.iter().map(|value| i64::from(*value)))
            .collect::<Vec<_>>();

        let matrix_statement = StructuredMatrixStatement {
            layers,
            rows,
            inner: cols,
            cols,
            max_abs_activation: 125,
            max_abs_weight: 125,
            max_abs_accumulator: 64_000_000,
        };
        let base_input = model
            .base_input()
            .iter()
            .map(|value| i64::from(*value) - 125)
            .collect::<Vec<_>>();
        let base_input_commitment = table_commitment(
            &base_input
                .iter()
                .copied()
                .map(ExtensionField::from_signed)
                .collect::<Vec<_>>(),
        );
        let weight_commitment = table_commitment(
            &weights
                .iter()
                .copied()
                .map(ExtensionField::from_signed)
                .collect::<Vec<_>>(),
        );
        let identity = ModelPcsIdentity {
            model_version: descriptor.model.model_version,
            batch: u32::try_from(rows).unwrap(),
            dimension: u32::try_from(cols).unwrap(),
            layers_per_bank: u32::try_from(layers).unwrap(),
            model_byte_root: descriptor.model.raw_blake3_root,
            pcs_suite_parameter_digest: descriptor.model.pcs_parameter_digest,
            base_input_commitment,
            weight_bank_commitments: vec![weight_commitment],
        };
        identity.validate().unwrap();
        let model_pcs_root = identity.commitment_root().unwrap();
        let work_digest = work_digest_from_roots(
            trace.challenge_digest,
            identity.model_byte_root,
            model_pcs_root,
            trace.final_activation_digest,
        );
        let binding = structured_forgematrix_public_binding(
            trace.challenge_digest,
            identity.model_byte_root,
            &identity,
            trace.final_activation_digest,
            work_digest,
            block.target,
            final_activation.len(),
        )
        .unwrap();
        let mut initialization_witness = empty_witness();
        for ((base, reduction), activation) in base_input
            .iter()
            .zip(&trace.initial_reductions)
            .zip(&initial)
        {
            append_reduction(&mut initialization_witness, *base, reduction, *activation);
        }
        let initialization_statement = StructuredTransitionStatement {
            layers: 1,
            rows,
            cols,
            max_abs_accumulator: 125,
            max_mask: 5_000,
        };
        let initialization_mask =
            StructuredMaskPolynomial::from_virtual_challenge(&trace.challenge_digest, rows, cols)
                .unwrap();
        let mut transition_witness = empty_witness();
        for layer in &trace.layers {
            for ((accumulator, reduction), activation) in layer
                .accumulators
                .iter()
                .zip(&layer.reductions)
                .zip(&layer.output)
            {
                append_reduction(
                    &mut transition_witness,
                    i64::from(*accumulator),
                    reduction,
                    i64::from(*activation),
                );
            }
        }
        let transition_statement = StructuredTransitionStatement {
            layers,
            rows,
            cols,
            max_abs_accumulator: 64_000_000,
            max_mask: 5_000,
        };
        let transition_mask =
            StructuredMaskPolynomial::from_challenge(&trace.challenge_digest, layers, rows, cols)
                .unwrap();
        let wiring_statement = StructuredWiringStatement {
            banks: 1,
            layers_per_bank: layers,
            rows,
            cols,
            max_abs_activation: 125,
        };
        FixtureData {
            challenge_digest: trace.challenge_digest,
            binding,
            identity,
            #[cfg(feature = "whir-prototype")]
            final_activation,
            final_activation_digest: trace.final_activation_digest,
            work_digest,
            work_target: block.target,
            initial,
            inputs,
            outputs,
            weights,
            accumulators,
            initialization_witness,
            transition_witness,
            initialization_statement,
            initialization_mask,
            matrix_statement,
            transition_statement,
            transition_mask,
            wiring_statement,
        }
    }

    fn fixture() -> (
        ModelPcsIdentity,
        StructuredForgeMatrixStatement,
        StructuredForgeMatrixProof,
    ) {
        let data = fixture_data();
        let matrix_proof = prove_structured_matrix_product(
            &data.binding,
            data.matrix_statement,
            &data.inputs,
            &data.weights,
            &data.accumulators,
        )
        .unwrap();
        let initialization_proof = prove_structured_transition(
            &data.binding,
            data.initialization_statement,
            &data.initialization_mask,
            &data.initialization_witness,
        )
        .unwrap();
        let transition_proof = prove_structured_transition(
            &data.binding,
            data.transition_statement,
            &data.transition_mask,
            &data.transition_witness,
        )
        .unwrap();
        let wiring_proof = prove_structured_wiring(
            &data.binding,
            data.wiring_statement,
            &data.initial,
            &data.inputs,
            &data.outputs,
        )
        .unwrap();
        assert_eq!(
            matrix_proof.weight_commitment,
            data.identity.weight_bank_commitments[0]
        );
        let statement = StructuredForgeMatrixStatement {
            challenge_digest: data.challenge_digest,
            public_binding: data.binding,
            model_byte_root: data.identity.model_byte_root,
            model_pcs_root: data.identity.commitment_root().unwrap(),
            final_activation_digest: data.final_activation_digest,
            work_digest: data.work_digest,
            work_target: data.work_target,
            base_input_commitment: data.identity.base_input_commitment,
            weight_commitments: data.identity.weight_bank_commitments.clone(),
            final_bank_output_commitment: *wiring_proof.output_commitments.last().unwrap(),
            initialization_statement: data.initialization_statement,
            initialization_mask: data.initialization_mask,
            matrix_statements: vec![data.matrix_statement],
            transition_statements: vec![data.transition_statement],
            transition_masks: vec![data.transition_mask],
            wiring_statement: data.wiring_statement,
        };
        let proof = StructuredForgeMatrixProof {
            protocol_version: STRUCTURED_AGGREGATE_VERSION,
            initialization_proof,
            matrix_proofs: vec![matrix_proof],
            transition_proofs: vec![transition_proof],
            wiring_proof,
            blake3_proof: b"authenticated-blake3".to_vec(),
            pcs_proof: b"authenticated-openings".to_vec(),
        };
        (data.identity, statement, proof)
    }

    #[cfg(feature = "whir-prototype")]
    fn whir_fixture() -> (
        ModelPcsIdentity,
        StructuredForgeMatrixStatement,
        StructuredForgeMatrixProof,
    ) {
        let data = fixture_data();
        let matrix_tables = structured_matrix_whir_tables(
            data.matrix_statement,
            &data.inputs,
            &data.weights,
            &data.accumulators,
        )
        .unwrap();
        let initialization_tables = structured_transition_whir_tables(
            data.initialization_statement,
            &data.initialization_witness,
        )
        .unwrap();
        let transition_tables =
            structured_transition_whir_tables(data.transition_statement, &data.transition_witness)
                .unwrap();
        let wiring_tables = structured_wiring_whir_tables(
            data.wiring_statement,
            &data.initial,
            &data.inputs,
            &data.outputs,
        )
        .unwrap();
        let model_commitments = StructuredWhirModelCommitmentSet::new(
            StructuredWhirModelMetadata {
                model_version: data.identity.model_version,
                batch: data.identity.batch,
                dimension: data.identity.dimension,
                layers_per_bank: data.identity.layers_per_bank,
                model_byte_root: data.identity.model_byte_root,
            },
            initialization_tables[0].clone(),
            vec![matrix_tables[1].clone()],
        )
        .unwrap();
        let identity = model_commitments.identity().clone();
        let trace_commitments = StructuredWhirCommitmentSet::new(
            matrix_tables
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != 1)
                .map(|(_, table)| table.clone())
                .chain(initialization_tables.iter().skip(1).cloned())
                .chain(transition_tables.iter().cloned())
                .chain(wiring_tables.iter().cloned())
                .collect(),
        )
        .unwrap();
        let trace_aliases = |tables: &[Vec<u64>]| {
            tables
                .iter()
                .map(|table| trace_commitments.commitment_for(table).unwrap())
                .collect::<Vec<_>>()
        };
        let matrix_aliases = [
            trace_commitments.commitment_for(&matrix_tables[0]).unwrap(),
            identity.weight_bank_commitments[0],
            trace_commitments.commitment_for(&matrix_tables[2]).unwrap(),
        ];
        let mut initialization_aliases = vec![identity.base_input_commitment];
        initialization_aliases.extend(trace_aliases(&initialization_tables[1..]));
        let transition_aliases = trace_aliases(&transition_tables);
        let wiring_aliases = trace_aliases(&wiring_tables);
        let work_digest = work_digest_from_roots(
            data.challenge_digest,
            identity.model_byte_root,
            identity.commitment_root().unwrap(),
            data.final_activation_digest,
        );
        let binding = structured_forgematrix_public_binding(
            data.challenge_digest,
            identity.model_byte_root,
            &identity,
            data.final_activation_digest,
            work_digest,
            data.work_target,
            data.final_activation.len(),
        )
        .unwrap();

        let matrix_proof = prove_structured_matrix_product_with_commitments(
            &binding,
            data.matrix_statement,
            &data.inputs,
            &data.weights,
            &data.accumulators,
            matrix_aliases,
        )
        .unwrap();
        let initialization_proof = prove_structured_transition_with_commitments(
            &binding,
            data.initialization_statement,
            &data.initialization_mask,
            &data.initialization_witness,
            initialization_aliases.clone(),
        )
        .unwrap();
        let transition_proof = prove_structured_transition_with_commitments(
            &binding,
            data.transition_statement,
            &data.transition_mask,
            &data.transition_witness,
            transition_aliases,
        )
        .unwrap();
        let wiring_proof = prove_structured_wiring_with_commitments(
            &binding,
            data.wiring_statement,
            &data.initial,
            &data.inputs,
            &data.outputs,
            wiring_aliases[0],
            vec![wiring_aliases[1]],
            vec![wiring_aliases[2]],
        )
        .unwrap();
        let statement = StructuredForgeMatrixStatement {
            challenge_digest: data.challenge_digest,
            public_binding: binding,
            model_byte_root: identity.model_byte_root,
            model_pcs_root: identity.commitment_root().unwrap(),
            final_activation_digest: data.final_activation_digest,
            work_digest,
            work_target: data.work_target,
            base_input_commitment: identity.base_input_commitment,
            weight_commitments: identity.weight_bank_commitments.clone(),
            final_bank_output_commitment: wiring_aliases[2],
            initialization_statement: data.initialization_statement,
            initialization_mask: data.initialization_mask,
            matrix_statements: vec![data.matrix_statement],
            transition_statements: vec![data.transition_statement],
            transition_masks: vec![data.transition_mask],
            wiring_statement: data.wiring_statement,
        };
        let mut proof = StructuredForgeMatrixProof {
            protocol_version: STRUCTURED_AGGREGATE_VERSION,
            initialization_proof,
            matrix_proofs: vec![matrix_proof],
            transition_proofs: vec![transition_proof],
            wiring_proof,
            blake3_proof: b"provisional".to_vec(),
            pcs_proof: Vec::new(),
        };
        let openings =
            collect_structured_forgematrix_openings(&statement, &proof, &identity).unwrap();
        proof.pcs_proof = prove_structured_whir_openings(
            &binding,
            &identity,
            &model_commitments,
            &trace_commitments,
            &openings,
        )
        .unwrap();
        let hash_statement = structured_blake3_statement(&statement, &proof, &identity).unwrap();
        proof.blake3_proof =
            crate::prove_structured_blake3(&hash_statement, &data.final_activation).unwrap();
        (identity, statement, proof)
    }

    fn canonical_matrix_envelope(statement: StructuredMatrixStatement) -> StructuredMatrixProof {
        let common_rounds = statement.inner.ilog2() as usize;
        let layer_rounds = statement.layers.ilog2() as usize;
        let mut rounds = vec![
            crate::StructuredMatrixRound {
                evaluations: vec![ExtensionElement { limbs: [0; 3] }; 3],
            };
            common_rounds
        ];
        rounds.extend(vec![
            crate::StructuredMatrixRound {
                evaluations: vec![ExtensionElement { limbs: [0; 3] }; 4],
            };
            layer_rounds
        ]);
        StructuredMatrixProof {
            protocol_version: crate::STRUCTURED_SUMCHECK_VERSION,
            activation_commitment: [0; 32],
            weight_commitment: [0; 32],
            accumulator_commitment: [0; 32],
            accumulator_evaluation: ExtensionElement { limbs: [0; 3] },
            rounds,
            activation_evaluation: ExtensionElement { limbs: [0; 3] },
            weight_evaluation: ExtensionElement { limbs: [0; 3] },
            transcript_digest: [0; 32],
        }
    }

    fn canonical_transition_envelope(
        statement: StructuredTransitionStatement,
    ) -> StructuredTransitionProof {
        let rounds = (statement.layers * statement.rows * statement.cols).ilog2() as usize;
        StructuredTransitionProof {
            protocol_version: crate::STRUCTURED_TRANSITION_VERSION,
            oracle_commitments: vec![[0; 32]; crate::STRUCTURED_TRANSITION_ORACLES],
            rounds: vec![
                crate::StructuredTransitionRound {
                    evaluations: vec![
                        ExtensionElement { limbs: [0; 3] };
                        crate::STRUCTURED_TRANSITION_MAX_DEGREE + 1
                    ],
                };
                rounds
            ],
            terminal_evaluations: vec![
                ExtensionElement { limbs: [0; 3] };
                crate::STRUCTURED_TRANSITION_ORACLES
            ],
            transcript_digest: [0; 32],
        }
    }

    fn canonical_wiring_envelope(statement: StructuredWiringStatement) -> StructuredWiringProof {
        let zero = ExtensionElement { limbs: [0; 3] };
        StructuredWiringProof {
            protocol_version: crate::STRUCTURED_WIRING_VERSION,
            initial_commitment: [0; 32],
            input_commitments: vec![[0; 32]; statement.banks],
            output_commitments: vec![[0; 32]; statement.banks],
            initial_evaluation: zero,
            input_shift_evaluations: vec![
                zero;
                statement.banks
                    * statement.layers_per_bank.ilog2() as usize
            ],
            input_first_evaluations: vec![zero; statement.banks],
            output_random_evaluations: vec![zero; statement.banks],
            output_last_evaluations: vec![zero; statement.banks],
            transcript_digest: [0; 32],
        }
    }

    #[test]
    fn production_candidate_is_verifier_only_and_exact() {
        let shape = StructuredForgeMatrixResearchShape::production_candidate();
        shape.validate_verifier_shape().unwrap();
        assert_eq!(
            PRODUCTION_V2_LAYERS as usize,
            shape.wiring_statement.banks * shape.wiring_statement.layers_per_bank
        );
        assert_eq!(
            shape.validate_materialized_shape(),
            Err(StructuredProofError::Matrix(
                StructuredSumcheckError::ResearchCap
            ))
        );
        for statement in shape.matrix_statements {
            assert_eq!(
                statement.validate_materialized_shape(),
                Err(StructuredSumcheckError::ResearchCap)
            );
        }
        for statement in shape.transition_statements {
            assert_eq!(
                statement.validate_materialized_shape(),
                Err(StructuredTransitionError::ResearchCap)
            );
        }
        assert_eq!(
            shape.wiring_statement.validate_materialized_shape(),
            Err(StructuredWiringError::ResearchCap)
        );

        let mut malformed = shape;
        malformed.matrix_statements[1].rows = 64;
        assert_eq!(
            malformed.validate_verifier_shape(),
            Err(StructuredProofError::ComponentShape)
        );

        let mut invalid = shape;
        invalid.transition_statements[2].layers = 3;
        assert_eq!(
            invalid.validate_verifier_shape(),
            Err(StructuredProofError::Transition(
                StructuredTransitionError::InvalidDimensions
            ))
        );
    }

    #[test]
    fn production_whole_frame_budget_rejects_individually_sized_children() {
        let shape = StructuredForgeMatrixResearchShape::production_candidate();
        shape.validate_verifier_shape().unwrap();

        let initialization_proof = canonical_transition_envelope(shape.initialization_statement);
        let matrix_proof = canonical_matrix_envelope(shape.matrix_statements[0]);
        let transition_proof = canonical_transition_envelope(shape.transition_statements[0]);
        let wiring_proof = canonical_wiring_envelope(shape.wiring_statement);
        assert_eq!(initialization_proof.canonical_size(), 14_443);
        assert_eq!(initialization_proof.encode().unwrap().len(), 14_443);
        assert_eq!(matrix_proof.canonical_size(), 1_771);
        assert_eq!(matrix_proof.encode().unwrap().len(), 1_771);
        assert_eq!(transition_proof.canonical_size(), 17_474);
        assert_eq!(transition_proof.encode().unwrap().len(), 17_474);
        assert_eq!(wiring_proof.canonical_size(), 1_036);
        assert_eq!(wiring_proof.encode().unwrap().len(), 1_036);

        let aggregate = StructuredForgeMatrixProof {
            protocol_version: STRUCTURED_AGGREGATE_VERSION,
            initialization_proof,
            matrix_proofs: vec![matrix_proof; PRODUCTION_BANKS],
            transition_proofs: vec![transition_proof; PRODUCTION_BANKS],
            wiring_proof,
            blake3_proof: vec![0],
            pcs_proof: vec![0],
        };
        // The two one-byte payloads make the envelope encodable; subtracting
        // them retains their canonical u32 length prefixes in the floor.
        let component_envelope_floor = aggregate.encode().unwrap().len() - 2;
        assert_eq!(
            component_envelope_floor,
            STRUCTURED_PRODUCTION_COMPONENT_FLOOR_BYTES
        );

        let current_v2_frame = crate::encode_forgematrix_proof(
            &crate::BlockProof::V2Reference(crate::ForgeMatrixV2CompactProof {
                algorithm_version: 0,
                proof_version: 0,
                nonce: 0,
                model_manifest_digest: [0; 32],
                challenge_digest: [0; 32],
                final_activation_digest: [0; 32],
                work_digest: [0; 32],
            }),
            [0; 32],
        )
        .unwrap();
        assert_eq!(
            current_v2_frame.len(),
            STRUCTURED_PRODUCTION_V2_WRAPPER_BYTES
        );
        assert_eq!(current_v2_frame.len() - crate::wire::WIRE_HEADER_BYTES, 177);

        // A future payload that preserves the current V2 identity fields and
        // appends one canonical sized aggregate needs this u32 length prefix.
        // MAX_PROOF_BYTES caps the complete frame, so the 16-byte wire header
        // and the 177 existing payload bytes must both remain in the budget.
        let aggregate_length_prefix = STRUCTURED_PRODUCTION_AGGREGATE_LENGTH_BYTES;
        let blake3_and_pcs_budget = crate::wire::MAX_PROOF_BYTES
            - current_v2_frame.len()
            - aggregate_length_prefix
            - component_envelope_floor;
        assert_eq!(
            blake3_and_pcs_budget,
            STRUCTURED_PRODUCTION_SHARED_ARGUMENT_BYTES
        );
        assert_eq!(STRUCTURED_PRODUCTION_SHARED_ARGUMENT_BYTES, 188_673);

        // These are the exact dictionary-free floors of the pinned n19 base
        // and three n31 weight candidates. One byte each is still required for
        // the hash and trace native payloads, so this is deliberately the most
        // optimistic representation of the current five-section split proof.
        let current_whir_floors = StructuredSplitV3ProductionBudget {
            blake3_argument_bytes: 1,
            base_model_native_bytes: 133_298,
            weight_model_native_bytes: [268_640; PRODUCTION_BANKS],
            trace_native_bytes: 1,
            trace_table_count: 1,
        };
        let usage = current_whir_floors.usage().unwrap();
        assert_eq!(usage.pcs_payload_bytes, 939_535);
        assert_eq!(usage.shared_argument_bytes, 939_536);
        assert_eq!(usage.complete_frame_bytes, 1_013_007);
        assert_eq!(
            current_whir_floors.ensure_fits(),
            Err(StructuredProductionBudgetError::ProofTooLarge {
                actual: 1_013_007,
                maximum: STRUCTURED_PRODUCTION_FRAME_BYTES,
            })
        );
        assert_eq!(
            usage.complete_frame_bytes - STRUCTURED_PRODUCTION_FRAME_BYTES,
            750_863
        );

        // Even if the hash, base, trace, and trace-table payloads were each
        // only one byte, equal n31 children could use at most 62,784 bytes.
        let non_weight_bytes = 1
            + STRUCTURED_PRODUCTION_SPLIT_PCS_FIXED_BYTES
            + STRUCTURED_PRODUCTION_SPLIT_PCS_TRACE_TABLE_BYTES
            + 1
            + 1;
        let optimistic_equal_weight_bytes =
            (STRUCTURED_PRODUCTION_SHARED_ARGUMENT_BYTES - non_weight_bytes) / PRODUCTION_BANKS;
        assert_eq!(optimistic_equal_weight_bytes, 62_784);

        // Retaining the exact n19 base floor leaves only 18,352 bytes for each
        // n31 child, before any native authentication dictionary is included.
        let non_weight_bytes_with_base = non_weight_bytes - 1 + 133_298;
        let equal_weight_bytes_with_base = (STRUCTURED_PRODUCTION_SHARED_ARGUMENT_BYTES
            - non_weight_bytes_with_base)
            / PRODUCTION_BANKS;
        assert_eq!(equal_weight_bytes_with_base, 18_352);

        const CURRENT_32768_ROW_BLAKE3_ZLIB_BYTES: usize = 209_693;
        const STRUCTURED_BLAKE3_ENVELOPE_BYTES: usize = 8 + 4 + 1 + 4;
        let current_blake3_checkpoint_bytes =
            CURRENT_32768_ROW_BLAKE3_ZLIB_BYTES + STRUCTURED_BLAKE3_ENVELOPE_BYTES;
        assert_eq!(current_blake3_checkpoint_bytes, 209_710);
        assert!(current_blake3_checkpoint_bytes > blake3_and_pcs_budget);
        let total_before_pcs_payload = current_v2_frame.len()
            + aggregate_length_prefix
            + component_envelope_floor
            + current_blake3_checkpoint_bytes;
        assert_eq!(total_before_pcs_payload, 283_181);
        let minimum_encodable_total = total_before_pcs_payload + 1;
        assert_eq!(minimum_encodable_total, 283_182);
        assert!(minimum_encodable_total > crate::wire::MAX_PROOF_BYTES);
    }

    #[test]
    fn production_whole_frame_budget_is_exact_and_overflow_safe() {
        let exact_trace_bytes = STRUCTURED_PRODUCTION_SHARED_ARGUMENT_BYTES
            - STRUCTURED_PRODUCTION_SPLIT_PCS_FIXED_BYTES
            - STRUCTURED_PRODUCTION_SPLIT_PCS_TRACE_TABLE_BYTES
            - 1
            - 1
            - PRODUCTION_BANKS;
        let exact = StructuredSplitV3ProductionBudget {
            blake3_argument_bytes: 1,
            base_model_native_bytes: 1,
            weight_model_native_bytes: [1; PRODUCTION_BANKS],
            trace_native_bytes: exact_trace_bytes,
            trace_table_count: 1,
        };
        let exact_usage = exact.ensure_fits().unwrap();
        assert_eq!(
            exact_usage.shared_argument_bytes,
            STRUCTURED_PRODUCTION_SHARED_ARGUMENT_BYTES
        );
        assert_eq!(
            exact_usage.complete_frame_bytes,
            STRUCTURED_PRODUCTION_FRAME_BYTES
        );

        let one_byte_over = StructuredSplitV3ProductionBudget {
            trace_native_bytes: exact_trace_bytes + 1,
            ..exact
        };
        assert_eq!(
            one_byte_over.ensure_fits(),
            Err(StructuredProductionBudgetError::ProofTooLarge {
                actual: STRUCTURED_PRODUCTION_FRAME_BYTES + 1,
                maximum: STRUCTURED_PRODUCTION_FRAME_BYTES,
            })
        );
        assert_eq!(
            StructuredSplitV3ProductionBudget {
                trace_table_count: 0,
                ..exact
            }
            .usage(),
            Err(StructuredProductionBudgetError::InvalidTraceTableCount)
        );
        assert_eq!(
            StructuredSplitV3ProductionBudget {
                trace_table_count: STRUCTURED_PRODUCTION_SPLIT_V3_MAX_TRACE_TABLES + 1,
                ..exact
            }
            .usage(),
            Err(StructuredProductionBudgetError::InvalidTraceTableCount)
        );
        assert_eq!(
            StructuredSplitV3ProductionBudget {
                blake3_argument_bytes: 0,
                ..exact
            }
            .usage(),
            Err(StructuredProductionBudgetError::EmptyPayload)
        );
        if let Some(unencodable_count) = (u32::MAX as usize).checked_add(1) {
            assert_eq!(
                StructuredSplitV3ProductionBudget {
                    trace_table_count: unencodable_count,
                    ..exact
                }
                .usage(),
                Err(StructuredProductionBudgetError::InvalidTraceTableCount)
            );
        }
        assert_eq!(
            StructuredSplitV3ProductionBudget {
                blake3_argument_bytes: usize::MAX,
                ..exact
            }
            .usage(),
            Err(StructuredProductionBudgetError::ArithmeticOverflow)
        );
    }

    #[test]
    fn batched_commitment_budget_pins_the_n33_deficit() {
        assert_eq!(STRUCTURED_BATCHED_PRODUCTION_COMPONENT_FLOOR_BYTES, 73_270);
        assert_eq!(STRUCTURED_BATCHED_PRODUCTION_SPLIT_PCS_FIXED_BYTES, 132);
        assert_eq!(STRUCTURED_BATCHED_PRODUCTION_PCS_BYTES, 188_677);
        assert_eq!(STRUCTURED_BATCHED_PRODUCTION_MODEL_NATIVE_BYTES, 188_540);

        let exact = StructuredBatchedProductionBudget {
            fixed_model_native_bytes: STRUCTURED_BATCHED_PRODUCTION_MODEL_NATIVE_BYTES,
            trace_native_bytes: 1,
            trace_table_count: 1,
        };
        assert_eq!(
            exact.ensure_fits().unwrap().complete_frame_bytes,
            STRUCTURED_PRODUCTION_FRAME_BYTES
        );
        assert_eq!(
            StructuredBatchedProductionBudget {
                fixed_model_native_bytes: STRUCTURED_BATCHED_PRODUCTION_MODEL_NATIVE_BYTES + 1,
                ..exact
            }
            .ensure_fits(),
            Err(StructuredProductionBudgetError::ProofTooLarge {
                actual: STRUCTURED_PRODUCTION_FRAME_BYTES + 1,
                maximum: STRUCTURED_PRODUCTION_FRAME_BYTES,
            })
        );

        const N33_DICTIONARY_FREE_FLOOR: usize = 293_906;
        let n33 = StructuredBatchedProductionBudget {
            fixed_model_native_bytes: N33_DICTIONARY_FREE_FLOOR,
            trace_native_bytes: 1,
            trace_table_count: 1,
        };
        let usage = n33.usage().unwrap();
        assert_eq!(usage.pcs_payload_bytes, 294_043);
        assert_eq!(usage.complete_frame_bytes, 367_510);
        assert_eq!(
            usage.complete_frame_bytes - STRUCTURED_PRODUCTION_FRAME_BYTES,
            105_366
        );
        assert_eq!(
            n33.ensure_fits(),
            Err(StructuredProductionBudgetError::ProofTooLarge {
                actual: 367_510,
                maximum: STRUCTURED_PRODUCTION_FRAME_BYTES,
            })
        );
        assert_eq!(
            StructuredBatchedProductionBudget {
                fixed_model_native_bytes: 0,
                trace_native_bytes: 1,
                trace_table_count: 1,
            }
            .usage(),
            Err(StructuredProductionBudgetError::EmptyPayload)
        );
        assert_eq!(
            StructuredBatchedProductionBudget {
                fixed_model_native_bytes: 1,
                trace_native_bytes: 0,
                trace_table_count: 1,
            }
            .usage(),
            Err(StructuredProductionBudgetError::EmptyPayload)
        );
        assert_eq!(
            StructuredBatchedProductionBudget {
                fixed_model_native_bytes: usize::MAX,
                trace_native_bytes: 1,
                trace_table_count: 1,
            }
            .usage(),
            Err(StructuredProductionBudgetError::ArithmeticOverflow)
        );
        assert_eq!(
            StructuredBatchedProductionBudget {
                fixed_model_native_bytes: 1,
                trace_native_bytes: 1,
                trace_table_count: 0,
            }
            .usage(),
            Err(StructuredProductionBudgetError::InvalidTraceTableCount)
        );
        assert_eq!(
            StructuredBatchedProductionBudget {
                fixed_model_native_bytes: 1,
                trace_native_bytes: 1,
                trace_table_count: STRUCTURED_PRODUCTION_SPLIT_V3_MAX_TRACE_TABLES + 1,
            }
            .usage(),
            Err(StructuredProductionBudgetError::InvalidTraceTableCount)
        );
        assert_eq!(
            StructuredBatchedProductionBudget {
                fixed_model_native_bytes: 1,
                trace_native_bytes: 1,
                trace_table_count: 452,
            }
            .usage(),
            Err(StructuredProductionBudgetError::InvalidTraceTableCount)
        );
    }

    #[test]
    fn aggregate_requires_every_component_and_authenticated_openings() {
        let (identity, statement, proof) = fixture();
        let encoded = proof.encode().unwrap();
        let decoded = StructuredForgeMatrixProof::decode(&encoded).unwrap();
        assert_eq!(decoded, proof);
        verify_structured_forgematrix_proof(
            &statement,
            &decoded,
            &identity,
            &TestPcs { accept: true },
            &TestBlake3 { accept: true },
        )
        .unwrap();
        assert_eq!(
            verify_structured_forgematrix_proof(
                &statement,
                &proof,
                &identity,
                &TestPcs { accept: false },
                &TestBlake3 { accept: true },
            ),
            Err(StructuredProofError::PcsRejected)
        );

        let mut wrong_weight = statement.clone();
        wrong_weight.weight_commitments[0][0] ^= 1;
        assert_eq!(
            verify_structured_forgematrix_proof(
                &wrong_weight,
                &proof,
                &identity,
                &TestPcs { accept: true },
                &TestBlake3 { accept: true },
            ),
            Err(StructuredProofError::ModelPcsIdentityMismatch)
        );

        let mut wrong_weight_proof = proof.clone();
        wrong_weight_proof.matrix_proofs[0].weight_commitment[0] ^= 1;
        assert_eq!(
            verify_structured_forgematrix_proof(
                &statement,
                &wrong_weight_proof,
                &identity,
                &TestPcs { accept: true },
                &TestBlake3 { accept: true },
            ),
            Err(StructuredProofError::WeightCommitment)
        );

        let mut wrong_accumulator = proof.clone();
        wrong_accumulator.matrix_proofs[0].accumulator_commitment[0] ^= 1;
        assert!(matches!(
            verify_structured_forgematrix_proof(
                &statement,
                &wrong_accumulator,
                &identity,
                &TestPcs { accept: true },
                &TestBlake3 { accept: true },
            ),
            Err(StructuredProofError::Wiring(
                StructuredWiringError::Commitment
            ))
        ));

        let mut wrong_final_output = statement.clone();
        wrong_final_output.final_bank_output_commitment[0] ^= 1;
        assert_eq!(
            verify_structured_forgematrix_proof(
                &wrong_final_output,
                &proof,
                &identity,
                &TestPcs { accept: true },
                &TestBlake3 { accept: true },
            ),
            Err(StructuredProofError::FinalBankOutputCommitment)
        );

        let mut wrong_binding = statement.clone();
        wrong_binding.public_binding[0] ^= 1;
        assert!(
            verify_structured_forgematrix_proof(
                &wrong_binding,
                &proof,
                &identity,
                &TestPcs { accept: true },
                &TestBlake3 { accept: true },
            )
            .is_err()
        );
    }

    #[test]
    fn trusted_model_identity_is_checked_and_forwarded_before_algebra() {
        let (identity, statement, proof) = fixture();
        let forwarding = ForwardingPcs {
            expected_identity: identity.clone(),
            called: AtomicBool::new(false),
        };
        verify_structured_forgematrix_proof(
            &statement,
            &proof,
            &identity,
            &forwarding,
            &TestBlake3 { accept: true },
        )
        .unwrap();
        assert!(forwarding.called.load(Ordering::SeqCst));

        let mut malformed = identity.clone();
        malformed.pcs_suite_parameter_digest = [0; 32];
        assert_eq!(
            verify_structured_forgematrix_proof(
                &statement,
                &proof,
                &malformed,
                &NeverPcs,
                &TestBlake3 { accept: true },
            ),
            Err(StructuredProofError::InvalidModelPcsIdentity)
        );

        let mut wrong_model_root = identity.clone();
        wrong_model_root.model_byte_root[0] ^= 1;
        assert_eq!(
            validate_model_pcs_identity(&statement, &wrong_model_root),
            Err(StructuredProofError::ModelPcsIdentityMismatch)
        );
        let mut wrong_base = identity.clone();
        wrong_base.base_input_commitment[0] ^= 1;
        assert_eq!(
            validate_model_pcs_identity(&statement, &wrong_base),
            Err(StructuredProofError::ModelPcsIdentityMismatch)
        );
        let mut wrong_weight = identity.clone();
        wrong_weight.weight_bank_commitments[0][0] ^= 1;
        assert_eq!(
            validate_model_pcs_identity(&statement, &wrong_weight),
            Err(StructuredProofError::ModelPcsIdentityMismatch)
        );

        let mut wrong_batch = identity.clone();
        wrong_batch.batch *= 2;
        assert_eq!(
            validate_model_pcs_identity(&statement, &wrong_batch),
            Err(StructuredProofError::ModelPcsIdentityMismatch)
        );
        let mut wrong_dimension = identity.clone();
        wrong_dimension.dimension *= 2;
        assert_eq!(
            validate_model_pcs_identity(&statement, &wrong_dimension),
            Err(StructuredProofError::ModelPcsIdentityMismatch)
        );
        let mut wrong_layers = identity.clone();
        wrong_layers.layers_per_bank *= 2;
        assert_eq!(
            validate_model_pcs_identity(&statement, &wrong_layers),
            Err(StructuredProofError::ModelPcsIdentityMismatch)
        );
        let mut wrong_bank_count = identity.clone();
        wrong_bank_count.weight_bank_commitments.push([0x5a; 32]);
        assert_eq!(
            validate_model_pcs_identity(&statement, &wrong_bank_count),
            Err(StructuredProofError::ModelPcsIdentityMismatch)
        );

        let mut two_bank_identity = identity.clone();
        two_bank_identity.weight_bank_commitments.push([0x5a; 32]);
        let mut two_bank_statement = statement.clone();
        two_bank_statement.wiring_statement.banks = 2;
        two_bank_statement.weight_commitments = two_bank_identity.weight_bank_commitments.clone();
        two_bank_statement.model_pcs_root = two_bank_identity.commitment_root().unwrap();
        validate_model_pcs_identity(&two_bank_statement, &two_bank_identity).unwrap();
        two_bank_identity.weight_bank_commitments.swap(0, 1);
        assert_eq!(
            validate_model_pcs_identity(&two_bank_statement, &two_bank_identity),
            Err(StructuredProofError::ModelPcsIdentityMismatch)
        );

        // The commitment root intentionally covers only ordered PCS
        // commitments. Suite and shape are instead frozen by the full identity
        // digest in the public transcript binding.
        let mut wrong_suite = identity.clone();
        wrong_suite.pcs_suite_parameter_digest[0] ^= 1;
        assert_eq!(
            wrong_suite.commitment_root().unwrap(),
            identity.commitment_root().unwrap()
        );
        assert_eq!(
            verify_structured_forgematrix_proof(
                &statement,
                &proof,
                &wrong_suite,
                &NeverPcs,
                &TestBlake3 { accept: true },
            ),
            Err(StructuredProofError::PublicBinding)
        );
    }

    #[test]
    fn opening_scopes_are_semantic_disjoint_and_share_one_cap() {
        let (identity, statement, proof) = fixture();
        let openings =
            collect_structured_forgematrix_openings(&statement, &proof, &identity).unwrap();
        let mut expected_fixed_commitments = std::iter::once(identity.base_input_commitment)
            .chain(identity.weight_bank_commitments.iter().copied())
            .collect::<Vec<_>>();
        expected_fixed_commitments.sort();
        assert_eq!(
            openings
                .fixed_model
                .iter()
                .map(|claim| claim.commitment)
                .collect::<Vec<_>>(),
            expected_fixed_commitments
        );
        let fixed_commitments = openings
            .fixed_model
            .iter()
            .map(|claim| claim.commitment)
            .collect::<BTreeSet<_>>();
        assert!(
            openings
                .trace
                .iter()
                .all(|claim| !fixed_commitments.contains(&claim.commitment))
        );

        let fixed = StructuredPcsOpeningClaim {
            commitment: [7; 32],
            point: vec![ExtensionElement { limbs: [1, 0, 0] }],
            evaluation: ExtensionElement { limbs: [2, 0, 0] },
        };
        let mut trace = fixed.clone();
        trace.point[0].limbs[0] = 3;
        assert_eq!(
            canonical_opening_set(vec![fixed.clone()], vec![trace]),
            Err(StructuredProofError::OpeningScopeConflict)
        );
        assert_eq!(
            canonical_opening_set(
                vec![fixed; MAX_STRUCTURED_OPENING_CLAIMS],
                vec![StructuredPcsOpeningClaim {
                    commitment: [8; 32],
                    point: vec![],
                    evaluation: ExtensionElement { limbs: [0; 3] },
                }],
            ),
            Err(StructuredProofError::OpeningCount)
        );
    }

    #[test]
    fn blake3_argument_and_work_digest_are_bound_fail_closed() {
        let (identity, statement, proof) = fixture();

        let mut missing_argument = proof.clone();
        missing_argument.blake3_proof.clear();
        assert_eq!(
            verify_structured_forgematrix_proof(
                &statement,
                &missing_argument,
                &identity,
                &TestPcs { accept: true },
                &TestBlake3 { accept: true },
            ),
            Err(StructuredProofError::MissingBlake3Proof)
        );

        assert_eq!(
            verify_structured_forgematrix_proof(
                &statement,
                &proof,
                &identity,
                &TestPcs { accept: true },
                &TestBlake3 { accept: false },
            ),
            Err(StructuredProofError::Blake3Rejected)
        );

        let mut wrong_digest = statement.clone();
        wrong_digest.final_activation_digest[0] ^= 1;
        assert_eq!(
            verify_structured_forgematrix_proof(
                &wrong_digest,
                &proof,
                &identity,
                &TestPcs { accept: true },
                &TestBlake3 { accept: true },
            ),
            Err(StructuredProofError::WorkDigest)
        );

        let mut wrong_work = statement.clone();
        wrong_work.work_digest[0] ^= 1;
        assert_eq!(
            verify_structured_forgematrix_proof(
                &wrong_work,
                &proof,
                &identity,
                &TestPcs { accept: true },
                &TestBlake3 { accept: true },
            ),
            Err(StructuredProofError::WorkDigest)
        );

        let mut impossible_target = statement.clone();
        impossible_target.work_target = [0; 32];
        assert_eq!(
            verify_structured_forgematrix_proof(
                &impossible_target,
                &proof,
                &identity,
                &TestPcs { accept: true },
                &TestBlake3 { accept: true },
            ),
            Err(StructuredProofError::HighHash)
        );

        let mut missing_model = statement.clone();
        missing_model.model_byte_root = [0; 32];
        assert_eq!(
            verify_structured_forgematrix_proof(
                &missing_model,
                &proof,
                &identity,
                &TestPcs { accept: true },
                &TestBlake3 { accept: true },
            ),
            Err(StructuredProofError::ModelPcsIdentityMismatch)
        );

        let mut different_challenge = statement.clone();
        different_challenge.challenge_digest[0] ^= 1;
        different_challenge.work_digest = work_digest_from_roots(
            different_challenge.challenge_digest,
            different_challenge.model_byte_root,
            different_challenge.model_pcs_root,
            different_challenge.final_activation_digest,
        );
        different_challenge.public_binding = structured_forgematrix_public_binding(
            different_challenge.challenge_digest,
            different_challenge.model_byte_root,
            &identity,
            different_challenge.final_activation_digest,
            different_challenge.work_digest,
            different_challenge.work_target,
            different_challenge.wiring_statement.rows * different_challenge.wiring_statement.cols,
        )
        .unwrap();
        assert!(
            verify_structured_forgematrix_proof(
                &different_challenge,
                &proof,
                &identity,
                &TestPcs { accept: true },
                &TestBlake3 { accept: true },
            )
            .is_err(),
            "a proof transcript must not replay under a different block challenge"
        );

        let mut different_valid_target = statement.clone();
        different_valid_target.work_target = different_valid_target.work_digest;
        assert_ne!(different_valid_target.work_target, statement.work_target);
        different_valid_target.public_binding = structured_forgematrix_public_binding(
            different_valid_target.challenge_digest,
            different_valid_target.model_byte_root,
            &identity,
            different_valid_target.final_activation_digest,
            different_valid_target.work_digest,
            different_valid_target.work_target,
            different_valid_target.wiring_statement.rows
                * different_valid_target.wiring_statement.cols,
        )
        .unwrap();
        assert!(
            verify_structured_forgematrix_proof(
                &different_valid_target,
                &proof,
                &identity,
                &TestPcs { accept: true },
                &TestBlake3 { accept: true },
            )
            .is_err(),
            "a proof transcript must not replay under a different valid target"
        );
    }

    #[test]
    fn blake3_statement_uses_the_committed_last_layer_opening() {
        let (identity, statement, proof) = fixture();
        let wiring = verify_structured_wiring_openings(
            &statement.public_binding,
            statement.wiring_statement,
            &proof.wiring_proof,
        )
        .unwrap();
        let hash_statement = structured_blake3_statement(&statement, &proof, &identity).unwrap();
        let cell_variables = statement.wiring_statement.cols.ilog2() as usize
            + statement.wiring_statement.rows.ilog2() as usize;
        assert_eq!(
            hash_statement.final_activation_point,
            wiring.final_output.point[..cell_variables]
        );
        assert_eq!(
            hash_statement.final_activation_evaluation,
            wiring.final_output.evaluation
        );
        assert_eq!(
            hash_statement.final_activation_len,
            statement.wiring_statement.rows * statement.wiring_statement.cols
        );
    }

    #[test]
    fn aggregate_parser_is_bounded_and_exact() {
        let (_, _, proof) = fixture();
        let canonical = proof.encode().unwrap();
        for length in [0, 1, 8, 12, canonical.len() - 1] {
            assert!(StructuredForgeMatrixProof::decode(&canonical[..length]).is_err());
        }
        let mut trailing = canonical.clone();
        trailing.push(0);
        assert_eq!(
            StructuredForgeMatrixProof::decode(&trailing),
            Err(StructuredProofError::Decode)
        );
        let mut missing_pcs = proof.clone();
        missing_pcs.pcs_proof.clear();
        assert_eq!(
            missing_pcs.encode(),
            Err(StructuredProofError::MissingPcsProof)
        );
        let mut missing_blake3 = proof.clone();
        missing_blake3.blake3_proof.clear();
        assert_eq!(
            missing_blake3.encode(),
            Err(StructuredProofError::MissingBlake3Proof)
        );
        assert_eq!(
            StructuredForgeMatrixProof::decode(&vec![0; MAX_STRUCTURED_AGGREGATE_PROOF_BYTES + 1]),
            Err(StructuredProofError::ProofTooLarge)
        );

        let stride = (canonical.len() / 257).max(1);
        for index in (0..canonical.len()).step_by(stride) {
            let mut mutated = canonical.clone();
            mutated[index] ^= 0x80;
            let decoded = std::panic::catch_unwind(|| StructuredForgeMatrixProof::decode(&mutated));
            assert!(decoded.is_ok(), "parser panicked for mutation at {index}");
            if let Ok(Ok(decoded)) = decoded {
                assert_eq!(decoded.encode().unwrap(), mutated);
            }
        }
    }

    #[cfg(feature = "whir-prototype")]
    #[test]
    fn aggregate_whir_openings_round_trip_and_fail_closed() {
        let (identity, statement, proof) = whir_fixture();
        let encoded = proof.encode().unwrap();
        let fixed_aggregate_bytes =
            encoded.len() - proof.blake3_proof.len() - proof.pcs_proof.len();
        assert_eq!(fixed_aggregate_bytes, 16_804);
        let blake3_statement = structured_blake3_statement(&statement, &proof, &identity).unwrap();
        let blake3_upper_bound = crate::structured_blake3::one_block_encoded_proof_bound(
            blake3_statement.final_activation_len,
        )
        .unwrap();
        assert_eq!(blake3_upper_bound, 87_556);
        assert!(proof.blake3_proof.len() <= blake3_upper_bound);
        let pcs_upper_bound =
            crate::whir_proof::structured_whir_encoded_proof_upper_bound(&proof.pcs_proof).unwrap();
        assert_eq!(pcs_upper_bound, 154_252);
        let aggregate_upper_bound = fixed_aggregate_bytes
            .checked_add(blake3_upper_bound)
            .and_then(|value| value.checked_add(pcs_upper_bound))
            .unwrap();
        assert_eq!(aggregate_upper_bound, 258_612);

        // A production V2 frame retains its current 193-byte wire encoding and
        // appends one u32-sized aggregate payload.
        let structured_wrapper_bytes = 193 + std::mem::size_of::<u32>();
        let wire_complete_upper_bound = structured_wrapper_bytes + aggregate_upper_bound;
        assert_eq!(wire_complete_upper_bound, 258_809);
        assert_eq!(
            crate::wire::MAX_PROOF_BYTES - wire_complete_upper_bound,
            3_335
        );
        assert!(proof.pcs_proof.len() <= pcs_upper_bound);
        assert!(encoded.len() <= aggregate_upper_bound);
        assert!(structured_wrapper_bytes + encoded.len() <= crate::wire::MAX_PROOF_BYTES);
        assert!(wire_complete_upper_bound <= crate::wire::MAX_PROOF_BYTES);
        assert!(proof.blake3_proof.len() < MAX_STRUCTURED_BLAKE3_PROOF_BYTES);
        let decoded = StructuredForgeMatrixProof::decode(&encoded).unwrap();
        let openings =
            collect_structured_forgematrix_openings(&statement, &decoded, &identity).unwrap();
        verify_structured_whir_openings(
            &statement.public_binding,
            &identity,
            &openings,
            &decoded.pcs_proof,
        )
        .unwrap();
        let blake3 = crate::StructuredBlake3StarkVerifier;
        verify_structured_forgematrix_proof(
            &statement,
            &decoded,
            &identity,
            &StructuredWhirPcsVerifier,
            &blake3,
        )
        .unwrap();

        let mut wrong_fixed_count = proof.clone();
        wrong_fixed_count.pcs_proof[12] ^= 1;
        assert_eq!(
            verify_structured_forgematrix_proof(
                &statement,
                &wrong_fixed_count,
                &identity,
                &StructuredWhirPcsVerifier,
                &blake3,
            ),
            Err(StructuredProofError::PcsRejected)
        );

        let mut wrong_opening = proof.clone();
        wrong_opening.matrix_proofs[0].activation_evaluation.limbs[0] ^= 1;
        assert!(
            verify_structured_forgematrix_proof(
                &statement,
                &wrong_opening,
                &identity,
                &StructuredWhirPcsVerifier,
                &blake3,
            )
            .is_err()
        );

        let mut truncated = proof.clone();
        truncated.pcs_proof.pop();
        assert_eq!(
            verify_structured_forgematrix_proof(
                &statement,
                &truncated,
                &identity,
                &StructuredWhirPcsVerifier,
                &blake3,
            ),
            Err(StructuredProofError::PcsRejected)
        );

        let mut corrupted_hash = proof.clone();
        corrupted_hash.blake3_proof[12] ^= 1;
        assert_eq!(
            verify_structured_forgematrix_proof(
                &statement,
                &corrupted_hash,
                &identity,
                &StructuredWhirPcsVerifier,
                &blake3,
            ),
            Err(StructuredProofError::Blake3Rejected)
        );
    }

    #[test]
    fn duplicate_openings_are_deduplicated_but_conflicts_fail() {
        let first = StructuredPcsOpeningClaim {
            commitment: [7; 32],
            point: vec![ExtensionElement { limbs: [1, 0, 0] }],
            evaluation: ExtensionElement { limbs: [2, 0, 0] },
        };
        let second = StructuredPcsOpeningClaim {
            commitment: [6; 32],
            point: vec![ExtensionElement { limbs: [3, 0, 0] }],
            evaluation: ExtensionElement { limbs: [4, 0, 0] },
        };
        assert_eq!(
            canonical_openings(vec![first.clone(), second.clone()]).unwrap(),
            canonical_openings(vec![second, first.clone()]).unwrap()
        );
        assert_eq!(
            canonical_openings(vec![first.clone(), first.clone()])
                .unwrap()
                .len(),
            1
        );
        let mut conflicting = first.clone();
        conflicting.evaluation.limbs[0] = 3;
        assert_eq!(
            canonical_openings(vec![first, conflicting]),
            Err(StructuredProofError::ConflictingOpening)
        );
    }
}
