//! BLS12-381 bank-batched matrix sumcheck authenticated by Dory.
//!
//! Activation, model-weight, and accumulator tables retain distinct
//! commitments. Smaller tables are zero-padded only in high variables so all
//! three use one Dory layout. The exact degree-two common rounds and
//! degree-three layer rounds reduce the matrix relation to three authenticated
//! multilinear openings.

use std::io::Cursor;
use std::path::Path;

use ark_ff::PrimeField;
use dory_pcs::primitives::{
    DoryDeserialize, DorySerialize,
    arithmetic::{Field, Group},
    serialization::{Compress, Validate},
    transcript::Transcript,
};
use thiserror::Error;

use crate::{
    StructuredMaskPolynomial, StructuredMatrixStatement, StructuredSumcheckError,
    StructuredTransitionStatement,
    dory_bls12_381_aggregate::{
        BlsDoryAggregateError, BlsDoryAggregateLayout, BlsDoryCommittedPolynomial,
        BlsDoryCompactRowSource, BlsDoryDeferredOpeningSet, BlsDoryOpeningClaim,
        MAX_BLS_DORY_AGGREGATE_BYTES, bounded_signed_code, bounded_signed_dictionary,
        commit_bls_dory_compact_row_source_with_scratch, commit_bls_dory_polynomial,
        commit_bls_dory_row_source_with_scratch, projected_bls_dory_aggregate_bytes,
        prove_bls_dory_deferred_opening_sets, verify_bls_dory_openings,
    },
    dory_bls12_381_execution_artifact::{
        BlsDoryExecutionAccumulatorArtifact, BlsDoryExecutionAccumulatorArtifactContext,
        BlsDoryExecutionAccumulatorColumn,
    },
    dory_bls12_381_prototype::{
        BlsDoryFr, BlsDoryGt, BlsDoryTranscript, DeterministicBlsDorySetup,
    },
    dory_bls12_381_streaming::BlsDoryRowSource,
    dory_bls12_381_transition::derive_transition_regular_row_from_mask,
    structured_sumcheck::{validate_streaming_tables, validate_tables},
};

#[cfg(test)]
use crate::dory_bls12_381_aggregate::prove_bls_dory_deferred_opening_sets_with_scratch;

/// Version of the scalar-field matrix transcript.
pub const BLS_DORY_MATRIX_VERSION: u16 = 1;
/// Production weights contain 128 * 4096 * 4096 = 2^31 elements.
pub const PRODUCTION_BLS_DORY_MATRIX_VARIABLES: usize = 31;
/// This checkpoint is not accepted by consensus.
pub const BLS_DORY_MATRIX_PRODUCTION_READY: bool = false;
/// Remaining gates on the scalar matrix path.
pub const BLS_DORY_MATRIX_PRODUCTION_BLOCKERS: [&str; 4] = [
    "the verified model-bank stream now publishes reusable authenticated coefficient artifacts and the matrix prover consumes them without a materialized i64 weight bank; bounded activations and model weights after their first Dory row use authenticated one-byte dictionary codes while accumulators retain canonical signed words, preserving the exact commitments, claims, and proof bytes and projecting all three production matrix sources at 8,259,944,664 bytes (7.7 GiB) without first-eight-generation fold files, but the exact n=31 path still lacks production disk, memory, and latency measurements",
    "the final production artifact commitments have not been generated and pinned in network parameters",
    "the executable algebraic union bound exists, but Dory knowledge soundness has not been independently reviewed",
    "the scalar matrix transcript, padding rule, and opening path have not received an external audit",
];

const PROOF_MAGIC: [u8; 8] = *b"CFBLSM01";
const PROOF_HEADER_BYTES: usize = 20;
const MAX_MATRIX_PROOF_BYTES: usize = 262_128;
const MAX_MATRIX_BINDING_BYTES: usize = 4_096;
const COMMON_ROUND_DEGREE: usize = 2;
const LAYER_ROUND_DEGREE: usize = 3;

/// Witness-free scalar matrix proof plus its canonical Dory opening payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsDoryMatrixProof {
    pub protocol_version: u16,
    pub padded_variables: u16,
    pub activation_commitment: BlsDoryGt,
    pub weight_commitment: BlsDoryGt,
    pub accumulator_commitment: BlsDoryGt,
    pub accumulator_evaluation: BlsDoryFr,
    pub rounds: Vec<Vec<BlsDoryFr>>,
    pub activation_evaluation: BlsDoryFr,
    pub weight_evaluation: BlsDoryFr,
    pub transcript_digest: [u8; 32],
    pub opening_proof: Vec<u8>,
}

pub(crate) struct PreparedBlsDoryMatrixProof {
    pub(crate) proof: BlsDoryMatrixProof,
    pub(crate) openings: BlsDoryDeferredOpeningSet,
}

/// The two transition tables that determine one matrix bank's input
/// activations. Layer zero consumes the last activation from `prior`; every
/// later layer consumes the preceding activation from `current`.
#[derive(Clone, Copy)]
pub(crate) struct BlsDoryExecutionArtifactMatrixInput<'a> {
    pub(crate) bank: usize,
    pub(crate) prior_statement: StructuredTransitionStatement,
    pub(crate) prior_mask: &'a StructuredMaskPolynomial,
    pub(crate) current_statement: StructuredTransitionStatement,
    pub(crate) current_mask: &'a StructuredMaskPolynomial,
}

#[derive(Clone, Copy)]
enum MatrixWeightProverSource<'a> {
    Signed(&'a [i64]),
    Precommitted(&'a BlsDoryCommittedPolynomial),
}

impl BlsDoryMatrixProof {
    /// Encode the exact statement-derived proof shape canonically.
    pub fn encode(
        &self,
        statement: StructuredMatrixStatement,
    ) -> Result<Vec<u8>, BlsDoryMatrixError> {
        self.encode_with_opening(statement, true)
    }

    pub(crate) fn encode_deferred(
        &self,
        statement: StructuredMatrixStatement,
    ) -> Result<Vec<u8>, BlsDoryMatrixError> {
        self.encode_with_opening(statement, false)
    }

    fn encode_with_opening(
        &self,
        statement: StructuredMatrixStatement,
        require_opening: bool,
    ) -> Result<Vec<u8>, BlsDoryMatrixError> {
        validate_proof_shape_with_opening(
            statement,
            self,
            usize::from(self.padded_variables),
            require_opening,
        )?;
        if !require_opening && !self.opening_proof.is_empty() {
            return Err(BlsDoryMatrixError::InvalidProofShape);
        }
        let common_rounds = statement.inner.ilog2() as usize;
        let layer_rounds = statement.layers.ilog2() as usize;
        let opening_len = u32::try_from(self.opening_proof.len())
            .map_err(|_| BlsDoryMatrixError::ProofTooLarge)?;
        let expected = matrix_wire_bytes(common_rounds, layer_rounds, self.opening_proof.len())?;
        let mut encoded = Vec::with_capacity(expected);
        encoded.extend_from_slice(&PROOF_MAGIC);
        encoded.extend_from_slice(&self.protocol_version.to_le_bytes());
        encoded.extend_from_slice(&self.padded_variables.to_le_bytes());
        encoded.extend_from_slice(&(common_rounds as u16).to_le_bytes());
        encoded.extend_from_slice(&(layer_rounds as u16).to_le_bytes());
        encoded.extend_from_slice(&opening_len.to_le_bytes());
        for commitment in [
            &self.activation_commitment,
            &self.weight_commitment,
            &self.accumulator_commitment,
        ] {
            append_serialized(&mut encoded, commitment)?;
        }
        append_serialized(&mut encoded, &self.accumulator_evaluation)?;
        for round in &self.rounds {
            for evaluation in round {
                append_serialized(&mut encoded, evaluation)?;
            }
        }
        append_serialized(&mut encoded, &self.activation_evaluation)?;
        append_serialized(&mut encoded, &self.weight_evaluation)?;
        encoded.extend_from_slice(&self.transcript_digest);
        encoded.extend_from_slice(&self.opening_proof);
        if encoded.len() != expected || encoded.len() > MAX_MATRIX_PROOF_BYTES {
            return Err(BlsDoryMatrixError::ProofTooLarge);
        }
        Ok(encoded)
    }

    /// Decode only the bounded shape implied by the trusted statement.
    pub fn decode(
        encoded: &[u8],
        statement: StructuredMatrixStatement,
    ) -> Result<Self, BlsDoryMatrixError> {
        let expected_variables = matrix_variables(statement)?;
        Self::decode_with_variables(encoded, statement, expected_variables)
    }

    /// Decode using the exact shared aggregate geometry selected by consensus.
    pub fn decode_with_variables(
        encoded: &[u8],
        statement: StructuredMatrixStatement,
        expected_variables: usize,
    ) -> Result<Self, BlsDoryMatrixError> {
        Self::decode_with_variables_and_opening(encoded, statement, expected_variables, true)
    }

    pub(crate) fn decode_deferred_with_variables(
        encoded: &[u8],
        statement: StructuredMatrixStatement,
        expected_variables: usize,
    ) -> Result<Self, BlsDoryMatrixError> {
        Self::decode_with_variables_and_opening(encoded, statement, expected_variables, false)
    }

    fn decode_with_variables_and_opening(
        encoded: &[u8],
        statement: StructuredMatrixStatement,
        expected_variables: usize,
        require_opening: bool,
    ) -> Result<Self, BlsDoryMatrixError> {
        statement.validate_verifier_shape()?;
        validate_target_variables(matrix_variables(statement)?, expected_variables)?;
        if encoded.len() < PROOF_HEADER_BYTES || encoded.len() > MAX_MATRIX_PROOF_BYTES {
            return Err(BlsDoryMatrixError::ProofTooLarge);
        }
        if encoded[..8] != PROOF_MAGIC {
            return Err(BlsDoryMatrixError::InvalidEncoding);
        }
        let protocol_version = read_u16(encoded, 8)?;
        let padded_variables = read_u16(encoded, 10)?;
        let common_rounds = read_u16(encoded, 12)? as usize;
        let layer_rounds = read_u16(encoded, 14)? as usize;
        let opening_len = read_u32(encoded, 16)? as usize;
        let expected_common = statement.inner.ilog2() as usize;
        let expected_layer = statement.layers.ilog2() as usize;
        if protocol_version != BLS_DORY_MATRIX_VERSION
            || usize::from(padded_variables) != expected_variables
            || common_rounds != expected_common
            || layer_rounds != expected_layer
            || (require_opening && opening_len == 0)
            || (!require_opening && opening_len != 0)
            || opening_len > MAX_BLS_DORY_AGGREGATE_BYTES
            || encoded.len() != matrix_wire_bytes(common_rounds, layer_rounds, opening_len)?
        {
            return Err(BlsDoryMatrixError::InvalidProofShape);
        }

        let mut reader = Cursor::new(&encoded[PROOF_HEADER_BYTES..]);
        let activation_commitment = read_serialized(&mut reader)?;
        let weight_commitment = read_serialized(&mut reader)?;
        let accumulator_commitment = read_serialized(&mut reader)?;
        let accumulator_evaluation = read_serialized(&mut reader)?;
        let mut rounds = Vec::with_capacity(common_rounds + layer_rounds);
        for _ in 0..common_rounds {
            rounds.push(read_fields(&mut reader, COMMON_ROUND_DEGREE + 1)?);
        }
        for _ in 0..layer_rounds {
            rounds.push(read_fields(&mut reader, LAYER_ROUND_DEGREE + 1)?);
        }
        let activation_evaluation = read_serialized(&mut reader)?;
        let weight_evaluation = read_serialized(&mut reader)?;
        let payload_offset = PROOF_HEADER_BYTES + reader.position() as usize;
        let digest_end = payload_offset
            .checked_add(32)
            .ok_or(BlsDoryMatrixError::InvalidProofShape)?;
        let transcript_digest = encoded
            .get(payload_offset..digest_end)
            .ok_or(BlsDoryMatrixError::InvalidProofShape)?
            .try_into()
            .map_err(|_| BlsDoryMatrixError::InvalidProofShape)?;
        let opening_proof = encoded
            .get(digest_end..)
            .ok_or(BlsDoryMatrixError::InvalidProofShape)?
            .to_vec();
        if opening_proof.len() != opening_len {
            return Err(BlsDoryMatrixError::InvalidProofShape);
        }
        let proof = Self {
            protocol_version,
            padded_variables,
            activation_commitment,
            weight_commitment,
            accumulator_commitment,
            accumulator_evaluation,
            rounds,
            activation_evaluation,
            weight_evaluation,
            transcript_digest,
            opening_proof,
        };
        if proof.encode_with_opening(statement, require_opening)? != encoded {
            return Err(BlsDoryMatrixError::InvalidEncoding);
        }
        Ok(proof)
    }
}

/// Errors from the scalar matrix checkpoint.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BlsDoryMatrixError {
    #[error("structured matrix input is invalid: {0}")]
    Structured(#[from] StructuredSumcheckError),
    #[error("Dory opening authentication failed: {0}")]
    Aggregate(#[from] BlsDoryAggregateError),
    #[error("padded matrix dimensions overflow or exceed this checkpoint")]
    InvalidDimensions,
    #[error("scalar matrix proof has the wrong fixed shape")]
    InvalidProofShape,
    #[error("matrix sumcheck round does not preserve the current claim")]
    RoundClaim,
    #[error("matrix terminal product relation is invalid")]
    TerminalClaim,
    #[error("matrix transcript digest mismatch")]
    Transcript,
    #[error("Dory claims do not match the matrix evaluations")]
    Opening,
    #[error("matrix public binding exceeds the bounded transcript limit")]
    PublicBindingTooLarge,
    #[error("matrix proof exceeds the network payload cap")]
    ProofTooLarge,
    #[error("matrix proof encoding is malformed or non-canonical")]
    InvalidEncoding,
    #[error("authenticated execution-accumulator artifact failed")]
    ExecutionArtifact,
    #[error("the BLS12-381 matrix checkpoint is not production ready")]
    NotProductionReady,
}

/// Fail closed while any production blocker remains.
pub fn require_bls_dory_matrix_production_ready() -> Result<(), BlsDoryMatrixError> {
    Err(BlsDoryMatrixError::NotProductionReady)
}

/// Project the canonical Dory opening payload for one production matrix bank.
pub fn projected_production_matrix_opening_bytes() -> Result<usize, BlsDoryMatrixError> {
    projected_bls_dory_aggregate_bytes(PRODUCTION_BLS_DORY_MATRIX_VARIABLES)
        .map_err(BlsDoryMatrixError::Aggregate)
}

/// Project the complete canonical production matrix proof.
pub fn projected_production_matrix_proof_bytes() -> Result<usize, BlsDoryMatrixError> {
    let statement = production_matrix_statement();
    matrix_wire_bytes(
        statement.inner.ilog2() as usize,
        statement.layers.ilog2() as usize,
        projected_production_matrix_opening_bytes()?,
    )
}

/// Prove the exact bank-batched matrix relation and authenticate its three openings.
#[allow(clippy::too_many_arguments)]
pub fn prove_bls_dory_matrix(
    binding: &[u8],
    statement: StructuredMatrixStatement,
    activations: &[i64],
    weights: &[i64],
    accumulators: &[i64],
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryMatrixProof, BlsDoryMatrixError> {
    let padded_variables = matrix_variables(statement)?;
    prove_bls_dory_matrix_at_variables(
        binding,
        statement,
        activations,
        weights,
        accumulators,
        padded_variables,
        setup,
    )
}

/// Prove the matrix relation at an exact shared aggregate geometry.
#[allow(clippy::too_many_arguments)]
pub fn prove_bls_dory_matrix_at_variables(
    binding: &[u8],
    statement: StructuredMatrixStatement,
    activations: &[i64],
    weights: &[i64],
    accumulators: &[i64],
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryMatrixProof, BlsDoryMatrixError> {
    let mut prepared = prove_bls_dory_matrix_deferred_at_variables(
        binding,
        statement,
        activations,
        weights,
        accumulators,
        padded_variables,
        setup,
    )?;
    let opening_binding = opening_binding(binding, &prepared.proof.transcript_digest);
    let aggregate_layout = BlsDoryAggregateLayout::new(
        padded_variables / 2,
        padded_variables - padded_variables / 2,
    )?;
    let (claims, opening_proof) = prove_bls_dory_deferred_opening_sets(
        &opening_binding,
        aggregate_layout,
        &[&prepared.openings],
        setup,
    )?;
    if claims != prepared.openings.claims() {
        return Err(BlsDoryMatrixError::Opening);
    }
    prepared.proof.opening_proof = opening_proof;
    verify_bls_dory_matrix_at_variables(
        binding,
        statement,
        &prepared.proof,
        padded_variables,
        setup,
    )?;
    Ok(prepared.proof)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_bls_dory_matrix_deferred_at_variables(
    binding: &[u8],
    statement: StructuredMatrixStatement,
    activations: &[i64],
    weights: &[i64],
    accumulators: &[i64],
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<PreparedBlsDoryMatrixProof, BlsDoryMatrixError> {
    prove_bls_dory_matrix_deferred_at_variables_with_optional_scratch(
        binding,
        statement,
        activations,
        MatrixWeightProverSource::Signed(weights),
        accumulators,
        padded_variables,
        setup,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_bls_dory_matrix_deferred_at_variables_with_scratch(
    binding: &[u8],
    statement: StructuredMatrixStatement,
    activations: &[i64],
    weights: &[i64],
    accumulators: &[i64],
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<PreparedBlsDoryMatrixProof, BlsDoryMatrixError> {
    prove_bls_dory_matrix_deferred_at_variables_with_optional_scratch(
        binding,
        statement,
        activations,
        MatrixWeightProverSource::Signed(weights),
        accumulators,
        padded_variables,
        setup,
        Some(scratch_directory),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_bls_dory_matrix_deferred_with_precommitted_weight_and_scratch(
    binding: &[u8],
    statement: StructuredMatrixStatement,
    activations: &[i64],
    weight: &BlsDoryCommittedPolynomial,
    accumulators: &[i64],
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<PreparedBlsDoryMatrixProof, BlsDoryMatrixError> {
    prove_bls_dory_matrix_deferred_at_variables_with_optional_scratch(
        binding,
        statement,
        activations,
        MatrixWeightProverSource::Precommitted(weight),
        accumulators,
        padded_variables,
        setup,
        Some(scratch_directory),
    )
}

/// Prove one matrix bank directly from the authenticated execution trace.
/// Only one Dory row is expanded at a time; the production activation and
/// accumulator vectors are never materialized.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_bls_dory_matrix_deferred_with_precommitted_weight_from_execution_artifact_and_scratch(
    binding: &[u8],
    statement: StructuredMatrixStatement,
    weight: &BlsDoryCommittedPolynomial,
    artifact: &mut BlsDoryExecutionAccumulatorArtifact,
    expected_context: BlsDoryExecutionAccumulatorArtifactContext,
    input: BlsDoryExecutionArtifactMatrixInput<'_>,
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<PreparedBlsDoryMatrixProof, BlsDoryMatrixError> {
    validate_precommitted_matrix_weight(statement, weight)?;
    let mut tables =
        ExecutionArtifactMatrixTables::new(statement, artifact, expected_context, input, setup)?;
    prove_bls_dory_matrix_deferred_from_table_source(
        binding,
        statement,
        &mut tables,
        MatrixWeightProverSource::Precommitted(weight),
        padded_variables,
        setup,
        Some(scratch_directory),
    )
}

fn validate_precommitted_matrix_weight(
    statement: StructuredMatrixStatement,
    weight: &BlsDoryCommittedPolynomial,
) -> Result<(), BlsDoryMatrixError> {
    statement.validate_verifier_shape()?;
    let weight_len = statement.table_lengths()?[1];
    if weight.explicit_coefficient_count() != weight_len {
        return Err(BlsDoryMatrixError::Structured(
            StructuredSumcheckError::InvalidLength,
        ));
    }
    Ok(())
}

fn validate_precommitted_matrix_tables(
    statement: StructuredMatrixStatement,
    activations: &[i64],
    weight: &BlsDoryCommittedPolynomial,
    accumulators: &[i64],
) -> Result<(), BlsDoryMatrixError> {
    validate_precommitted_matrix_weight(statement, weight)?;
    let [activation_len, _, accumulator_len] = statement.table_lengths()?;
    if activations.len() != activation_len || accumulators.len() != accumulator_len {
        return Err(BlsDoryMatrixError::Structured(
            StructuredSumcheckError::InvalidLength,
        ));
    }
    if activations
        .iter()
        .any(|value| value.unsigned_abs() > statement.max_abs_activation)
        || accumulators
            .iter()
            .any(|value| value.unsigned_abs() > statement.max_abs_accumulator)
    {
        return Err(BlsDoryMatrixError::Structured(
            StructuredSumcheckError::ValueOutOfRange,
        ));
    }
    Ok(())
}

fn accumulate_weight_partials(
    statement: StructuredMatrixStatement,
    source: MatrixWeightProverSource<'_>,
    column_weights: &[BlsDoryFr],
    output: &mut [BlsDoryFr],
) -> Result<(), BlsDoryMatrixError> {
    let expected = statement
        .layers
        .checked_mul(statement.inner)
        .and_then(|count| count.checked_mul(statement.cols))
        .ok_or(BlsDoryMatrixError::InvalidDimensions)?;
    if column_weights.len() != statement.cols || output.len() != statement.layers * statement.inner
    {
        return Err(BlsDoryMatrixError::InvalidDimensions);
    }
    let mut visited = 0usize;
    let mut value_out_of_range = false;
    let mut accumulate = |index: usize, coefficient: BlsDoryFr| {
        let partial = index / statement.cols;
        let column = index % statement.cols;
        output[partial] = output[partial] + coefficient * column_weights[column];
        visited += 1;
    };
    match source {
        MatrixWeightProverSource::Signed(weights) => {
            for (index, weight) in weights.iter().copied().enumerate() {
                accumulate(index, BlsDoryFr::from_i64(weight));
            }
        }
        MatrixWeightProverSource::Precommitted(weight) => {
            weight.for_each_explicit_coefficient(&mut |index, coefficient| {
                if !scalar_within_signed_bound(coefficient, statement.max_abs_weight) {
                    value_out_of_range = true;
                }
                accumulate(index, coefficient);
            })?;
        }
    }
    if value_out_of_range {
        return Err(BlsDoryMatrixError::Structured(
            StructuredSumcheckError::ValueOutOfRange,
        ));
    }
    if visited != expected {
        return Err(BlsDoryMatrixError::InvalidDimensions);
    }
    Ok(())
}

fn scalar_within_signed_bound(value: BlsDoryFr, maximum: u64) -> bool {
    [value, -value].into_iter().any(|candidate| {
        let limbs = candidate.0.into_bigint();
        let limbs = limbs.as_ref();
        limbs[0] <= maximum && limbs[1..].iter().all(|limb| *limb == 0)
    })
}

trait MatrixTableProverSource {
    #[allow(clippy::too_many_arguments)]
    fn commit_activation(
        &mut self,
        statement: StructuredMatrixStatement,
        padded_variables: usize,
        nu: usize,
        sigma: usize,
        setup: &DeterministicBlsDorySetup,
        scratch_directory: Option<&Path>,
    ) -> Result<BlsDoryCommittedPolynomial, BlsDoryMatrixError>;

    #[allow(clippy::too_many_arguments)]
    fn commit_accumulator(
        &mut self,
        statement: StructuredMatrixStatement,
        padded_variables: usize,
        nu: usize,
        sigma: usize,
        setup: &DeterministicBlsDorySetup,
        scratch_directory: Option<&Path>,
    ) -> Result<BlsDoryCommittedPolynomial, BlsDoryMatrixError>;

    fn evaluate_accumulator(
        &mut self,
        statement: StructuredMatrixStatement,
        layer_weights: &[BlsDoryFr],
        row_weights: &[BlsDoryFr],
        column_weights: &[BlsDoryFr],
    ) -> Result<BlsDoryFr, BlsDoryMatrixError>;

    fn activation_partials(
        &mut self,
        statement: StructuredMatrixStatement,
        row_weights: &[BlsDoryFr],
    ) -> Result<Vec<BlsDoryFr>, BlsDoryMatrixError>;
}

struct MaterializedMatrixTables<'a> {
    activations: &'a [i64],
    accumulators: &'a [i64],
}

impl MatrixTableProverSource for MaterializedMatrixTables<'_> {
    fn commit_activation(
        &mut self,
        statement: StructuredMatrixStatement,
        padded_variables: usize,
        nu: usize,
        sigma: usize,
        setup: &DeterministicBlsDorySetup,
        scratch_directory: Option<&Path>,
    ) -> Result<BlsDoryCommittedPolynomial, BlsDoryMatrixError> {
        commit_bounded_signed_table(
            self.activations,
            statement.max_abs_activation,
            padded_variables,
            nu,
            sigma,
            setup,
            scratch_directory,
        )
    }

    fn commit_accumulator(
        &mut self,
        _statement: StructuredMatrixStatement,
        padded_variables: usize,
        nu: usize,
        sigma: usize,
        setup: &DeterministicBlsDorySetup,
        scratch_directory: Option<&Path>,
    ) -> Result<BlsDoryCommittedPolynomial, BlsDoryMatrixError> {
        commit_signed_table(
            self.accumulators,
            padded_variables,
            nu,
            sigma,
            setup,
            scratch_directory,
        )
    }

    fn evaluate_accumulator(
        &mut self,
        statement: StructuredMatrixStatement,
        layer_weights: &[BlsDoryFr],
        row_weights: &[BlsDoryFr],
        column_weights: &[BlsDoryFr],
    ) -> Result<BlsDoryFr, BlsDoryMatrixError> {
        evaluate_accumulators(
            statement,
            self.accumulators,
            layer_weights,
            row_weights,
            column_weights,
        )
    }

    fn activation_partials(
        &mut self,
        statement: StructuredMatrixStatement,
        row_weights: &[BlsDoryFr],
    ) -> Result<Vec<BlsDoryFr>, BlsDoryMatrixError> {
        if row_weights.len() != statement.rows {
            return Err(BlsDoryMatrixError::InvalidDimensions);
        }
        let partial_len = statement
            .layers
            .checked_mul(statement.inner)
            .ok_or(BlsDoryMatrixError::InvalidDimensions)?;
        let mut partials = Vec::with_capacity(partial_len);
        for layer in 0..statement.layers {
            for common in 0..statement.inner {
                let mut activation = BlsDoryFr::zero();
                for (row, row_weight) in row_weights.iter().copied().enumerate() {
                    let index = (layer * statement.rows + row) * statement.inner + common;
                    activation =
                        activation + BlsDoryFr::from_i64(self.activations[index]) * row_weight;
                }
                partials.push(activation);
            }
        }
        Ok(partials)
    }
}

#[allow(clippy::too_many_arguments)]
fn prove_bls_dory_matrix_deferred_at_variables_with_optional_scratch(
    binding: &[u8],
    statement: StructuredMatrixStatement,
    activations: &[i64],
    weight_source: MatrixWeightProverSource<'_>,
    accumulators: &[i64],
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: Option<&Path>,
) -> Result<PreparedBlsDoryMatrixProof, BlsDoryMatrixError> {
    match weight_source {
        MatrixWeightProverSource::Signed(weights) if scratch_directory.is_some() => {
            validate_streaming_tables(statement, activations, weights, accumulators)?;
        }
        MatrixWeightProverSource::Signed(weights) => {
            validate_tables(statement, activations, weights, accumulators)?;
        }
        MatrixWeightProverSource::Precommitted(weight) => {
            validate_precommitted_matrix_tables(statement, activations, weight, accumulators)?;
        }
    }
    let mut tables = MaterializedMatrixTables {
        activations,
        accumulators,
    };
    prove_bls_dory_matrix_deferred_from_table_source(
        binding,
        statement,
        &mut tables,
        weight_source,
        padded_variables,
        setup,
        scratch_directory,
    )
}

#[allow(clippy::too_many_arguments)]
fn prove_bls_dory_matrix_deferred_from_table_source<T: MatrixTableProverSource>(
    binding: &[u8],
    statement: StructuredMatrixStatement,
    tables: &mut T,
    weight_source: MatrixWeightProverSource<'_>,
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: Option<&Path>,
) -> Result<PreparedBlsDoryMatrixProof, BlsDoryMatrixError> {
    if binding.len() > MAX_MATRIX_BINDING_BYTES {
        return Err(BlsDoryMatrixError::PublicBindingTooLarge);
    }
    validate_target_variables(matrix_variables(statement)?, padded_variables)?;
    if padded_variables > setup.max_log_n() {
        return Err(BlsDoryMatrixError::InvalidDimensions);
    }
    let nu = padded_variables / 2;
    let sigma = padded_variables - nu;
    let aggregate_layout = BlsDoryAggregateLayout::new(nu, sigma)?;
    let activation_polynomial = tables.commit_activation(
        statement,
        padded_variables,
        nu,
        sigma,
        setup,
        scratch_directory,
    )?;
    let weight_polynomial = match weight_source {
        MatrixWeightProverSource::Signed(weights) => commit_bounded_signed_table(
            weights,
            statement.max_abs_weight,
            padded_variables,
            nu,
            sigma,
            setup,
            scratch_directory,
        )?,
        MatrixWeightProverSource::Precommitted(weight) => {
            if scratch_directory.is_none() || !weight.matches_layout(aggregate_layout, setup) {
                return Err(BlsDoryMatrixError::InvalidDimensions);
            }
            weight.clone()
        }
    };
    let accumulator_polynomial = tables.commit_accumulator(
        statement,
        padded_variables,
        nu,
        sigma,
        setup,
        scratch_directory,
    )?;
    let activation_commitment = activation_polynomial.commitment();
    let weight_commitment = weight_polynomial.commitment();
    let accumulator_commitment = accumulator_polynomial.commitment();

    let mut transcript = matrix_transcript(
        binding,
        statement,
        &activation_commitment,
        &weight_commitment,
        &accumulator_commitment,
    );
    let layer_point = challenge_vector(
        &mut transcript,
        b"layer-point",
        statement.layers.ilog2() as usize,
    );
    let row_point = challenge_vector(
        &mut transcript,
        b"row-point",
        statement.rows.ilog2() as usize,
    );
    let col_point = challenge_vector(
        &mut transcript,
        b"column-point",
        statement.cols.ilog2() as usize,
    );
    let accumulator_point = accumulator_point(&col_point, &row_point, &layer_point);
    let layer_weights = equality_weights(&layer_point);
    let row_weights = equality_weights(&row_point);
    let col_weights = equality_weights(&col_point);
    let accumulator_evaluation =
        tables.evaluate_accumulator(statement, &layer_weights, &row_weights, &col_weights)?;
    transcript.append_field(b"accumulator-evaluation", &accumulator_evaluation);
    let partial_len = statement
        .layers
        .checked_mul(statement.inner)
        .ok_or(BlsDoryMatrixError::InvalidDimensions)?;
    let mut layer_selector = Vec::with_capacity(partial_len);
    let mut activation_partial = tables.activation_partials(statement, &row_weights)?;
    let mut weight_partial = vec![BlsDoryFr::zero(); partial_len];
    for layer_weight in layer_weights.iter().copied() {
        layer_selector.extend(std::iter::repeat_n(layer_weight, statement.inner));
    }
    accumulate_weight_partials(statement, weight_source, &col_weights, &mut weight_partial)?;

    let mut claim = accumulator_evaluation;
    let common_rounds = statement.inner.ilog2() as usize;
    let layer_rounds = statement.layers.ilog2() as usize;
    let mut rounds = Vec::with_capacity(common_rounds + layer_rounds);
    let mut common_sumcheck_point = Vec::with_capacity(common_rounds);
    let mut layer_sumcheck_point = Vec::with_capacity(layer_rounds);
    for round_index in 0..common_rounds {
        let evaluations = product_round(
            &layer_selector,
            &activation_partial,
            &weight_partial,
            COMMON_ROUND_DEGREE,
        )?;
        if evaluations[0] + evaluations[1] != claim {
            return Err(BlsDoryMatrixError::RoundClaim);
        }
        absorb_round(&mut transcript, b"common-round", round_index, &evaluations);
        let challenge = transcript.challenge_scalar(b"common-challenge");
        claim = evaluate_samples(&evaluations, challenge)?;
        common_sumcheck_point.push(challenge);
        layer_selector = fold(&layer_selector, challenge)?;
        activation_partial = fold(&activation_partial, challenge)?;
        weight_partial = fold(&weight_partial, challenge)?;
        rounds.push(evaluations);
    }
    for round_index in 0..layer_rounds {
        let evaluations = product_round(
            &layer_selector,
            &activation_partial,
            &weight_partial,
            LAYER_ROUND_DEGREE,
        )?;
        if evaluations[0] + evaluations[1] != claim {
            return Err(BlsDoryMatrixError::RoundClaim);
        }
        absorb_round(&mut transcript, b"layer-round", round_index, &evaluations);
        let challenge = transcript.challenge_scalar(b"layer-challenge");
        claim = evaluate_samples(&evaluations, challenge)?;
        layer_sumcheck_point.push(challenge);
        layer_selector = fold(&layer_selector, challenge)?;
        activation_partial = fold(&activation_partial, challenge)?;
        weight_partial = fold(&weight_partial, challenge)?;
        rounds.push(evaluations);
    }
    if layer_selector.len() != 1
        || activation_partial.len() != 1
        || weight_partial.len() != 1
        || claim != layer_selector[0] * activation_partial[0] * weight_partial[0]
    {
        return Err(BlsDoryMatrixError::TerminalClaim);
    }
    let activation_evaluation = activation_partial[0];
    let weight_evaluation = weight_partial[0];
    transcript.append_field(b"activation-evaluation", &activation_evaluation);
    transcript.append_field(b"weight-evaluation", &weight_evaluation);
    let transcript_digest = transcript.digest();

    let activation_point =
        activation_point(&common_sumcheck_point, &row_point, &layer_sumcheck_point);
    let weight_point = weight_point(&col_point, &common_sumcheck_point, &layer_sumcheck_point);
    let opening_points = vec![
        pad_point(&activation_point, padded_variables)?,
        pad_point(&weight_point, padded_variables)?,
        pad_point(&accumulator_point, padded_variables)?,
    ];
    let polynomials = vec![
        activation_polynomial,
        weight_polynomial,
        accumulator_polynomial,
    ];
    let expected_claims = matrix_opening_claims(
        [
            activation_commitment,
            weight_commitment,
            accumulator_commitment,
        ],
        &opening_points,
        [
            activation_evaluation,
            weight_evaluation,
            accumulator_evaluation,
        ],
    );
    let openings = BlsDoryDeferredOpeningSet::new(polynomials, vec![0, 1, 2], opening_points)?;
    if openings.claims() != expected_claims {
        return Err(BlsDoryMatrixError::Opening);
    }

    let proof = BlsDoryMatrixProof {
        protocol_version: BLS_DORY_MATRIX_VERSION,
        padded_variables: u16::try_from(padded_variables)
            .map_err(|_| BlsDoryMatrixError::InvalidDimensions)?,
        activation_commitment,
        weight_commitment,
        accumulator_commitment,
        accumulator_evaluation,
        rounds,
        activation_evaluation,
        weight_evaluation,
        transcript_digest,
        opening_proof: Vec::new(),
    };
    verify_bls_dory_matrix_deferred_at_variables(
        binding,
        statement,
        &proof,
        padded_variables,
        setup,
    )?;
    Ok(PreparedBlsDoryMatrixProof { proof, openings })
}

/// Verify the matrix sumcheck and all three Dory openings without table witnesses.
pub fn verify_bls_dory_matrix(
    binding: &[u8],
    statement: StructuredMatrixStatement,
    proof: &BlsDoryMatrixProof,
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDoryMatrixError> {
    let padded_variables = matrix_variables(statement)?;
    verify_bls_dory_matrix_at_variables(binding, statement, proof, padded_variables, setup)
}

/// Verify a matrix proof against the exact shared aggregate geometry.
pub fn verify_bls_dory_matrix_at_variables(
    binding: &[u8],
    statement: StructuredMatrixStatement,
    proof: &BlsDoryMatrixProof,
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDoryMatrixError> {
    let claims = verify_bls_dory_matrix_deferred_at_variables(
        binding,
        statement,
        proof,
        padded_variables,
        setup,
    )?;
    let binding = opening_binding(binding, &proof.transcript_digest);
    let aggregate_layout = BlsDoryAggregateLayout::new(
        padded_variables / 2,
        padded_variables - padded_variables / 2,
    )?;
    verify_bls_dory_openings(
        &binding,
        aggregate_layout,
        &claims,
        &proof.opening_proof,
        setup,
    )?;
    Ok(())
}

pub(crate) fn verify_bls_dory_matrix_deferred_at_variables(
    binding: &[u8],
    statement: StructuredMatrixStatement,
    proof: &BlsDoryMatrixProof,
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<Vec<BlsDoryOpeningClaim>, BlsDoryMatrixError> {
    if binding.len() > MAX_MATRIX_BINDING_BYTES {
        return Err(BlsDoryMatrixError::PublicBindingTooLarge);
    }
    statement.validate_verifier_shape()?;
    validate_target_variables(matrix_variables(statement)?, padded_variables)?;
    if padded_variables > setup.max_log_n() {
        return Err(BlsDoryMatrixError::InvalidDimensions);
    }
    validate_deferred_proof_shape(statement, proof, padded_variables)?;
    let mut transcript = matrix_transcript(
        binding,
        statement,
        &proof.activation_commitment,
        &proof.weight_commitment,
        &proof.accumulator_commitment,
    );
    let layer_point = challenge_vector(
        &mut transcript,
        b"layer-point",
        statement.layers.ilog2() as usize,
    );
    let row_point = challenge_vector(
        &mut transcript,
        b"row-point",
        statement.rows.ilog2() as usize,
    );
    let col_point = challenge_vector(
        &mut transcript,
        b"column-point",
        statement.cols.ilog2() as usize,
    );
    transcript.append_field(b"accumulator-evaluation", &proof.accumulator_evaluation);
    let mut claim = proof.accumulator_evaluation;
    let common_rounds = statement.inner.ilog2() as usize;
    let layer_rounds = statement.layers.ilog2() as usize;
    let mut common_sumcheck_point = Vec::with_capacity(common_rounds);
    let mut layer_sumcheck_point = Vec::with_capacity(layer_rounds);
    for (index, evaluations) in proof.rounds.iter().enumerate() {
        let (degree, phase, challenge_label, phase_index) = if index < common_rounds {
            (
                COMMON_ROUND_DEGREE,
                b"common-round".as_slice(),
                b"common-challenge".as_slice(),
                index,
            )
        } else {
            (
                LAYER_ROUND_DEGREE,
                b"layer-round".as_slice(),
                b"layer-challenge".as_slice(),
                index - common_rounds,
            )
        };
        if evaluations.len() != degree + 1 || evaluations[0] + evaluations[1] != claim {
            return Err(BlsDoryMatrixError::RoundClaim);
        }
        absorb_round(&mut transcript, phase, phase_index, evaluations);
        let challenge = transcript.challenge_scalar(challenge_label);
        claim = evaluate_samples(evaluations, challenge)?;
        if index < common_rounds {
            common_sumcheck_point.push(challenge);
        } else {
            layer_sumcheck_point.push(challenge);
        }
    }
    let selector = equality_evaluation(&layer_point, &layer_sumcheck_point)?;
    if claim != selector * proof.activation_evaluation * proof.weight_evaluation {
        return Err(BlsDoryMatrixError::TerminalClaim);
    }
    transcript.append_field(b"activation-evaluation", &proof.activation_evaluation);
    transcript.append_field(b"weight-evaluation", &proof.weight_evaluation);
    if transcript.digest() != proof.transcript_digest {
        return Err(BlsDoryMatrixError::Transcript);
    }

    let activation_point =
        activation_point(&common_sumcheck_point, &row_point, &layer_sumcheck_point);
    let weight_point = weight_point(&col_point, &common_sumcheck_point, &layer_sumcheck_point);
    let accumulator_point = accumulator_point(&col_point, &row_point, &layer_point);
    let opening_points = vec![
        pad_point(&activation_point, padded_variables)?,
        pad_point(&weight_point, padded_variables)?,
        pad_point(&accumulator_point, padded_variables)?,
    ];
    let claims = matrix_opening_claims(
        [
            proof.activation_commitment,
            proof.weight_commitment,
            proof.accumulator_commitment,
        ],
        &opening_points,
        [
            proof.activation_evaluation,
            proof.weight_evaluation,
            proof.accumulator_evaluation,
        ],
    );
    Ok(claims)
}

fn production_matrix_statement() -> StructuredMatrixStatement {
    StructuredMatrixStatement {
        layers: 128,
        rows: 128,
        inner: 4096,
        cols: 4096,
        max_abs_activation: 125,
        max_abs_weight: 125,
        max_abs_accumulator: 64_000_000,
    }
}

fn validate_deferred_proof_shape(
    statement: StructuredMatrixStatement,
    proof: &BlsDoryMatrixProof,
    expected_variables: usize,
) -> Result<(), BlsDoryMatrixError> {
    validate_proof_shape_with_opening(statement, proof, expected_variables, false)
}

fn validate_proof_shape_with_opening(
    statement: StructuredMatrixStatement,
    proof: &BlsDoryMatrixProof,
    expected_variables: usize,
    require_opening: bool,
) -> Result<(), BlsDoryMatrixError> {
    statement.validate_verifier_shape()?;
    validate_target_variables(matrix_variables(statement)?, expected_variables)?;
    let common_rounds = statement.inner.ilog2() as usize;
    let layer_rounds = statement.layers.ilog2() as usize;
    if proof.protocol_version != BLS_DORY_MATRIX_VERSION
        || usize::from(proof.padded_variables) != expected_variables
        || proof.rounds.len() != common_rounds + layer_rounds
        || proof
            .rounds
            .iter()
            .take(common_rounds)
            .any(|round| round.len() != COMMON_ROUND_DEGREE + 1)
        || proof
            .rounds
            .iter()
            .skip(common_rounds)
            .any(|round| round.len() != LAYER_ROUND_DEGREE + 1)
        || (require_opening && proof.opening_proof.is_empty())
        || proof.opening_proof.len() > MAX_BLS_DORY_AGGREGATE_BYTES
    {
        return Err(BlsDoryMatrixError::InvalidProofShape);
    }
    Ok(())
}

fn validate_target_variables(
    minimum_variables: usize,
    target_variables: usize,
) -> Result<(), BlsDoryMatrixError> {
    if target_variables < minimum_variables || target_variables > 64 {
        return Err(BlsDoryMatrixError::InvalidDimensions);
    }
    Ok(())
}

fn matrix_variables(statement: StructuredMatrixStatement) -> Result<usize, BlsDoryMatrixError> {
    statement.validate_verifier_shape()?;
    statement
        .table_lengths()?
        .into_iter()
        .map(|length| length.ilog2() as usize)
        .max()
        .ok_or(BlsDoryMatrixError::InvalidDimensions)
}

fn matrix_wire_bytes(
    common_rounds: usize,
    layer_rounds: usize,
    opening_bytes: usize,
) -> Result<usize, BlsDoryMatrixError> {
    let scalar_count = common_rounds
        .checked_mul(COMMON_ROUND_DEGREE + 1)
        .and_then(|count| {
            layer_rounds
                .checked_mul(LAYER_ROUND_DEGREE + 1)
                .and_then(|layer| count.checked_add(layer))
        })
        .and_then(|count| count.checked_add(3))
        .ok_or(BlsDoryMatrixError::ProofTooLarge)?;
    PROOF_HEADER_BYTES
        .checked_add(3 * BlsDoryGt::identity().compressed_size())
        .and_then(|size| {
            size.checked_add(scalar_count.checked_mul(BlsDoryFr::zero().compressed_size())?)
        })
        .and_then(|size| size.checked_add(32))
        .and_then(|size| size.checked_add(opening_bytes))
        .filter(|size| *size <= MAX_MATRIX_PROOF_BYTES)
        .ok_or(BlsDoryMatrixError::ProofTooLarge)
}

fn append_serialized<T: DorySerialize>(
    output: &mut Vec<u8>,
    value: &T,
) -> Result<(), BlsDoryMatrixError> {
    value
        .serialize_compressed(output)
        .map_err(|_| BlsDoryMatrixError::InvalidEncoding)
}

fn read_serialized<T: DoryDeserialize>(
    reader: &mut Cursor<&[u8]>,
) -> Result<T, BlsDoryMatrixError> {
    T::deserialize_with_mode(reader, Compress::Yes, Validate::Yes)
        .map_err(|_| BlsDoryMatrixError::InvalidEncoding)
}

fn read_fields(
    reader: &mut Cursor<&[u8]>,
    count: usize,
) -> Result<Vec<BlsDoryFr>, BlsDoryMatrixError> {
    (0..count).map(|_| read_serialized(reader)).collect()
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, BlsDoryMatrixError> {
    let value: [u8; 2] = bytes
        .get(offset..offset + 2)
        .ok_or(BlsDoryMatrixError::InvalidProofShape)?
        .try_into()
        .map_err(|_| BlsDoryMatrixError::InvalidProofShape)?;
    Ok(u16::from_le_bytes(value))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, BlsDoryMatrixError> {
    let value: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or(BlsDoryMatrixError::InvalidProofShape)?
        .try_into()
        .map_err(|_| BlsDoryMatrixError::InvalidProofShape)?;
    Ok(u32::from_le_bytes(value))
}

fn matrix_transcript(
    binding: &[u8],
    statement: StructuredMatrixStatement,
    activation_commitment: &BlsDoryGt,
    weight_commitment: &BlsDoryGt,
    accumulator_commitment: &BlsDoryGt,
) -> BlsDoryTranscript {
    let mut transcript = BlsDoryTranscript::new(b"matrix-sumcheck");
    transcript.append_bytes(b"protocol-version", &BLS_DORY_MATRIX_VERSION.to_le_bytes());
    transcript.append_bytes(b"public-binding", binding);
    for value in [
        statement.layers as u64,
        statement.rows as u64,
        statement.inner as u64,
        statement.cols as u64,
        statement.max_abs_activation,
        statement.max_abs_weight,
        statement.max_abs_accumulator,
    ] {
        transcript.append_bytes(b"statement-field", &value.to_le_bytes());
    }
    transcript.append_group(b"activation-commitment", activation_commitment);
    transcript.append_group(b"weight-commitment", weight_commitment);
    transcript.append_group(b"accumulator-commitment", accumulator_commitment);
    transcript
}

fn challenge_vector(
    transcript: &mut BlsDoryTranscript,
    label: &[u8],
    count: usize,
) -> Vec<BlsDoryFr> {
    (0..count)
        .map(|index| {
            transcript.append_bytes(b"point-index", &(index as u64).to_le_bytes());
            transcript.challenge_scalar(label)
        })
        .collect()
}

fn absorb_round(
    transcript: &mut BlsDoryTranscript,
    phase: &[u8],
    index: usize,
    evaluations: &[BlsDoryFr],
) {
    transcript.append_bytes(b"round-phase", phase);
    transcript.append_bytes(b"round-index", &(index as u64).to_le_bytes());
    transcript.append_bytes(b"round-count", &(evaluations.len() as u64).to_le_bytes());
    for evaluation in evaluations {
        transcript.append_field(b"round-evaluation", evaluation);
    }
}

fn opening_binding(binding: &[u8], transcript_digest: &[u8; 32]) -> [u8; 32] {
    let mut hasher =
        blake3::Hasher::new_derive_key("CMFD/FORGEMATRIX/BLS-DORY-MATRIX-OPENING-BINDING/V1");
    hasher.update(&(binding.len() as u64).to_le_bytes());
    hasher.update(binding);
    hasher.update(transcript_digest);
    *hasher.finalize().as_bytes()
}

#[derive(Clone, Copy)]
enum ExecutionArtifactMatrixTable {
    Activation,
    Accumulator,
}

struct ExecutionArtifactMatrixTables<'a, 'm> {
    artifact: &'a mut BlsDoryExecutionAccumulatorArtifact,
    context: BlsDoryExecutionAccumulatorArtifactContext,
    input: BlsDoryExecutionArtifactMatrixInput<'m>,
    statement: StructuredMatrixStatement,
    cells_per_layer: usize,
    cached_column: Option<BlsDoryExecutionAccumulatorColumn>,
    cached_start: usize,
    cached_len: usize,
    io: Vec<i32>,
}

impl<'a, 'm> ExecutionArtifactMatrixTables<'a, 'm> {
    fn new(
        statement: StructuredMatrixStatement,
        artifact: &'a mut BlsDoryExecutionAccumulatorArtifact,
        expected_context: BlsDoryExecutionAccumulatorArtifactContext,
        input: BlsDoryExecutionArtifactMatrixInput<'m>,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<Self, BlsDoryMatrixError> {
        statement.validate_verifier_shape()?;
        let cells_per_layer = statement
            .rows
            .checked_mul(statement.cols)
            .ok_or(BlsDoryMatrixError::InvalidDimensions)?;
        let prior_layers = if input.bank == 0 {
            1
        } else {
            expected_context.layers_per_bank()
        };
        if artifact.context() != expected_context
            || expected_context.setup_identity() != setup.identity()
            || input.bank >= expected_context.banks()
            || statement.layers != expected_context.layers_per_bank()
            || statement.rows != expected_context.canonical_rows()
            || statement.inner != expected_context.canonical_columns()
            || statement.cols != expected_context.canonical_columns()
            || cells_per_layer != expected_context.cells_per_column()
            || input.current_statement.layers != statement.layers
            || input.current_statement.rows != statement.rows
            || input.current_statement.cols != statement.cols
            || input.current_statement.max_abs_accumulator != statement.max_abs_accumulator
            || input.prior_statement.layers != prior_layers
            || input.prior_statement.rows != statement.rows
            || input.prior_statement.cols != statement.cols
            || (input.bank > 0
                && input.prior_statement.max_abs_accumulator != statement.max_abs_accumulator)
        {
            return Err(BlsDoryMatrixError::ExecutionArtifact);
        }
        input
            .prior_mask
            .validate(input.prior_statement)
            .map_err(|_| BlsDoryMatrixError::ExecutionArtifact)?;
        input
            .current_mask
            .validate(input.current_statement)
            .map_err(|_| BlsDoryMatrixError::ExecutionArtifact)?;
        let challenge = expected_context.challenge_identity();
        let expected_virtual = StructuredMaskPolynomial::from_virtual_challenge(
            &challenge,
            expected_context.canonical_rows(),
            expected_context.canonical_columns(),
        )
        .map_err(|_| BlsDoryMatrixError::ExecutionArtifact)?;
        let current_layer_offset = input
            .bank
            .checked_mul(expected_context.layers_per_bank())
            .and_then(|offset| u32::try_from(offset).ok())
            .ok_or(BlsDoryMatrixError::ExecutionArtifact)?;
        let expected_current = StructuredMaskPolynomial::from_challenge_at_layer_offset(
            &challenge,
            current_layer_offset,
            expected_context.layers_per_bank(),
            expected_context.canonical_rows(),
            expected_context.canonical_columns(),
        )
        .map_err(|_| BlsDoryMatrixError::ExecutionArtifact)?;
        let expected_prior = if input.bank == 0 {
            expected_virtual
        } else {
            let prior_layer_offset = (input.bank - 1)
                .checked_mul(expected_context.layers_per_bank())
                .and_then(|offset| u32::try_from(offset).ok())
                .ok_or(BlsDoryMatrixError::ExecutionArtifact)?;
            StructuredMaskPolynomial::from_challenge_at_layer_offset(
                &challenge,
                prior_layer_offset,
                expected_context.layers_per_bank(),
                expected_context.canonical_rows(),
                expected_context.canonical_columns(),
            )
            .map_err(|_| BlsDoryMatrixError::ExecutionArtifact)?
        };
        if input.prior_mask != &expected_prior || input.current_mask != &expected_current {
            return Err(BlsDoryMatrixError::ExecutionArtifact);
        }
        Ok(Self {
            artifact,
            context: expected_context,
            input,
            statement,
            cells_per_layer,
            cached_column: None,
            cached_start: 0,
            cached_len: 0,
            io: vec![0; expected_context.authentication_chunk_cells()],
        })
    }

    fn ensure_cached_chunk(
        &mut self,
        column: BlsDoryExecutionAccumulatorColumn,
        cell: usize,
    ) -> Result<(), BlsDoryMatrixError> {
        if cell >= self.cells_per_layer {
            return Err(BlsDoryMatrixError::InvalidDimensions);
        }
        let chunk_cells = self.context.authentication_chunk_cells();
        let chunk_start = cell / chunk_cells * chunk_cells;
        let chunk_len = (self.cells_per_layer - chunk_start).min(chunk_cells);
        if self.cached_column == Some(column)
            && self.cached_start == chunk_start
            && self.cached_len == chunk_len
        {
            return Ok(());
        }
        self.cached_column = None;
        self.cached_start = 0;
        self.cached_len = 0;
        self.artifact
            .read_column_segment(column, chunk_start, &mut self.io[..chunk_len])
            .map_err(|_| BlsDoryMatrixError::ExecutionArtifact)?;
        self.cached_column = Some(column);
        self.cached_start = chunk_start;
        self.cached_len = chunk_len;
        Ok(())
    }

    fn table_len(&self, table: ExecutionArtifactMatrixTable) -> Result<usize, BlsDoryMatrixError> {
        let lengths = self.statement.table_lengths()?;
        Ok(match table {
            ExecutionArtifactMatrixTable::Activation => lengths[0],
            ExecutionArtifactMatrixTable::Accumulator => lengths[2],
        })
    }

    fn read_values(
        &mut self,
        table: ExecutionArtifactMatrixTable,
        start: usize,
        output: &mut [i64],
    ) -> Result<(), BlsDoryMatrixError> {
        let table_len = self.table_len(table)?;
        let end = start
            .checked_add(output.len())
            .filter(|end| *end <= table_len)
            .ok_or(BlsDoryMatrixError::InvalidDimensions)?;
        let mut cursor = start;
        let mut written = 0usize;
        while cursor < end {
            let matrix_layer = cursor / self.cells_per_layer;
            let cell = cursor % self.cells_per_layer;
            let column = match table {
                ExecutionArtifactMatrixTable::Accumulator => {
                    BlsDoryExecutionAccumulatorColumn::BankLayer {
                        bank: self.input.bank,
                        layer: matrix_layer,
                    }
                }
                ExecutionArtifactMatrixTable::Activation if matrix_layer == 0 => {
                    if self.input.bank == 0 {
                        BlsDoryExecutionAccumulatorColumn::Initialization
                    } else {
                        BlsDoryExecutionAccumulatorColumn::BankLayer {
                            bank: self.input.bank - 1,
                            layer: self.context.layers_per_bank() - 1,
                        }
                    }
                }
                ExecutionArtifactMatrixTable::Activation => {
                    BlsDoryExecutionAccumulatorColumn::BankLayer {
                        bank: self.input.bank,
                        layer: matrix_layer - 1,
                    }
                }
            };
            self.ensure_cached_chunk(column, cell)?;
            let cache_offset = cell
                .checked_sub(self.cached_start)
                .ok_or(BlsDoryMatrixError::ExecutionArtifact)?;
            let take = (end - cursor)
                .min(self.cells_per_layer - cell)
                .min(self.cached_len - cache_offset);
            let cached = &self.io[cache_offset..cache_offset + take];
            match table {
                ExecutionArtifactMatrixTable::Accumulator => {
                    for (destination, value) in
                        output[written..written + take].iter_mut().zip(cached)
                    {
                        let value = i64::from(*value);
                        if value.unsigned_abs() > self.statement.max_abs_accumulator {
                            return Err(BlsDoryMatrixError::Structured(
                                StructuredSumcheckError::ValueOutOfRange,
                            ));
                        }
                        *destination = value;
                    }
                }
                ExecutionArtifactMatrixTable::Activation => {
                    let (transition_statement, mask, transition_layer) = if matrix_layer == 0 {
                        (
                            self.input.prior_statement,
                            self.input.prior_mask,
                            self.input.prior_statement.layers - 1,
                        )
                    } else {
                        (
                            self.input.current_statement,
                            self.input.current_mask,
                            matrix_layer - 1,
                        )
                    };
                    let transition_start = transition_layer
                        .checked_mul(self.cells_per_layer)
                        .and_then(|start| start.checked_add(cell))
                        .ok_or(BlsDoryMatrixError::InvalidDimensions)?;
                    for (offset, (destination, accumulator)) in output[written..written + take]
                        .iter_mut()
                        .zip(cached)
                        .enumerate()
                    {
                        let index = transition_start
                            .checked_add(offset)
                            .ok_or(BlsDoryMatrixError::InvalidDimensions)?;
                        let mask_value = mask
                            .value_at_boolean_index_prevalidated(transition_statement, index)
                            .map_err(|_| BlsDoryMatrixError::ExecutionArtifact)?;
                        let activation = derive_transition_regular_row_from_mask(
                            transition_statement,
                            index,
                            i64::from(*accumulator),
                            mask_value,
                        )
                        .map_err(|_| BlsDoryMatrixError::ExecutionArtifact)?
                        .activation;
                        if activation.unsigned_abs() > self.statement.max_abs_activation {
                            return Err(BlsDoryMatrixError::Structured(
                                StructuredSumcheckError::ValueOutOfRange,
                            ));
                        }
                        *destination = activation;
                    }
                }
            }
            cursor += take;
            written += take;
        }
        Ok(())
    }

    fn row_source<'s>(
        &'s mut self,
        table: ExecutionArtifactMatrixTable,
        rows: usize,
        columns: usize,
        code_maximum: Option<u8>,
    ) -> Result<ExecutionArtifactMatrixRowSource<'s, 'a, 'm>, BlsDoryMatrixError> {
        let explicit_scalars = self.table_len(table)?;
        let dictionary = code_maximum
            .and_then(bounded_signed_dictionary)
            .filter(|_| explicit_scalars > columns)
            .unwrap_or_else(|| vec![BlsDoryFr::zero()]);
        let use_codes = dictionary.len() > 1;
        Ok(ExecutionArtifactMatrixRowSource {
            tables: self,
            table,
            rows,
            columns,
            explicit_scalars,
            word_scalar_count: if use_codes { columns } else { explicit_scalars },
            word_group_len: if use_codes { columns } else { explicit_scalars },
            dictionary,
            code_maximum: use_codes.then_some(code_maximum).flatten(),
            values: vec![0; columns],
        })
    }
}

struct ExecutionArtifactMatrixRowSource<'s, 'a, 'm> {
    tables: &'s mut ExecutionArtifactMatrixTables<'a, 'm>,
    table: ExecutionArtifactMatrixTable,
    rows: usize,
    columns: usize,
    explicit_scalars: usize,
    word_scalar_count: usize,
    word_group_len: usize,
    dictionary: Vec<BlsDoryFr>,
    code_maximum: Option<u8>,
    values: Vec<i64>,
}

impl ExecutionArtifactMatrixRowSource<'_, '_, '_> {
    fn load_row(&mut self, row_index: usize) -> Result<(), BlsDoryMatrixError> {
        if row_index >= self.rows || self.values.len() != self.columns {
            return Err(BlsDoryMatrixError::InvalidDimensions);
        }
        self.values.fill(0);
        let start = row_index
            .checked_mul(self.columns)
            .ok_or(BlsDoryMatrixError::InvalidDimensions)?;
        let count = self
            .explicit_scalars
            .saturating_sub(start)
            .min(self.columns);
        if count > 0 {
            self.tables
                .read_values(self.table, start, &mut self.values[..count])?;
        }
        Ok(())
    }
}

impl BlsDoryRowSource for ExecutionArtifactMatrixRowSource<'_, '_, '_> {
    type Error = BlsDoryMatrixError;

    fn rows(&self) -> usize {
        self.rows
    }

    fn columns(&self) -> usize {
        self.columns
    }

    fn explicit_scalar_count(&self) -> usize {
        self.explicit_scalars
    }

    fn read_row(
        &mut self,
        row_index: usize,
        output: &mut [BlsDoryFr],
    ) -> Result<usize, Self::Error> {
        if output.len() != self.columns {
            return Err(BlsDoryMatrixError::InvalidDimensions);
        }
        self.load_row(row_index)?;
        for (scalar, value) in output.iter_mut().zip(&self.values) {
            *scalar = BlsDoryFr::from_i64(*value);
        }
        Ok(output.len())
    }
}

impl BlsDoryCompactRowSource for ExecutionArtifactMatrixRowSource<'_, '_, '_> {
    type Error = BlsDoryMatrixError;

    fn rows(&self) -> usize {
        self.rows
    }

    fn columns(&self) -> usize {
        self.columns
    }

    fn explicit_scalar_count(&self) -> usize {
        self.explicit_scalars
    }

    fn word_scalar_count(&self) -> usize {
        self.word_scalar_count
    }

    fn word_group_len(&self) -> usize {
        self.word_group_len
    }

    fn signed_word_selectors(&self) -> u64 {
        1
    }

    fn dictionary(&self) -> &[BlsDoryFr] {
        &self.dictionary
    }

    fn read_word_row(
        &mut self,
        row_index: usize,
        output: &mut [u64],
    ) -> Result<usize, Self::Error> {
        if output.len() != self.columns {
            return Err(BlsDoryMatrixError::InvalidDimensions);
        }
        self.load_row(row_index)?;
        for (word, value) in output.iter_mut().zip(&self.values) {
            *word = u64::from_le_bytes(value.to_le_bytes());
        }
        Ok(output.len())
    }

    fn read_code_row(&mut self, row_index: usize, output: &mut [u8]) -> Result<usize, Self::Error> {
        if output.len() != self.columns {
            return Err(BlsDoryMatrixError::InvalidDimensions);
        }
        let maximum = self
            .code_maximum
            .ok_or(BlsDoryMatrixError::InvalidDimensions)?;
        self.load_row(row_index)?;
        for (code, value) in output.iter_mut().zip(&self.values) {
            *code = bounded_signed_code(*value, maximum)
                .ok_or(BlsDoryMatrixError::ExecutionArtifact)?;
        }
        Ok(output.len())
    }
}

fn map_execution_artifact_commit_error(error: BlsDoryAggregateError) -> BlsDoryMatrixError {
    if error == BlsDoryAggregateError::CoefficientSource {
        BlsDoryMatrixError::ExecutionArtifact
    } else {
        BlsDoryMatrixError::Aggregate(error)
    }
}

impl MatrixTableProverSource for ExecutionArtifactMatrixTables<'_, '_> {
    fn commit_activation(
        &mut self,
        statement: StructuredMatrixStatement,
        padded_variables: usize,
        nu: usize,
        sigma: usize,
        setup: &DeterministicBlsDorySetup,
        scratch_directory: Option<&Path>,
    ) -> Result<BlsDoryCommittedPolynomial, BlsDoryMatrixError> {
        let scratch_directory = scratch_directory.ok_or(BlsDoryMatrixError::ExecutionArtifact)?;
        let padded_len = 1usize
            .checked_shl(padded_variables as u32)
            .ok_or(BlsDoryMatrixError::InvalidDimensions)?;
        let activation_len = statement.table_lengths()?[0];
        if activation_len == 0 || !activation_len.is_power_of_two() || activation_len > padded_len {
            return Err(BlsDoryMatrixError::InvalidDimensions);
        }
        let rows = 1usize
            .checked_shl(nu as u32)
            .ok_or(BlsDoryMatrixError::InvalidDimensions)?;
        let columns = 1usize
            .checked_shl(sigma as u32)
            .ok_or(BlsDoryMatrixError::InvalidDimensions)?;
        let code_maximum = u8::try_from(statement.max_abs_activation)
            .ok()
            .filter(|maximum| *maximum <= 127);
        let mut source = self.row_source(
            ExecutionArtifactMatrixTable::Activation,
            rows,
            columns,
            code_maximum,
        )?;
        if source.code_maximum.is_some() && activation_len.is_multiple_of(columns) {
            return commit_bls_dory_compact_row_source_with_scratch(
                &mut source,
                nu,
                sigma,
                setup,
                scratch_directory,
            )
            .map_err(map_execution_artifact_commit_error);
        }
        commit_bls_dory_row_source_with_scratch(&mut source, nu, sigma, setup, scratch_directory)
            .map_err(map_execution_artifact_commit_error)
    }

    fn commit_accumulator(
        &mut self,
        statement: StructuredMatrixStatement,
        padded_variables: usize,
        nu: usize,
        sigma: usize,
        setup: &DeterministicBlsDorySetup,
        scratch_directory: Option<&Path>,
    ) -> Result<BlsDoryCommittedPolynomial, BlsDoryMatrixError> {
        let scratch_directory = scratch_directory.ok_or(BlsDoryMatrixError::ExecutionArtifact)?;
        let padded_len = 1usize
            .checked_shl(padded_variables as u32)
            .ok_or(BlsDoryMatrixError::InvalidDimensions)?;
        let accumulator_len = statement.table_lengths()?[2];
        if accumulator_len == 0
            || !accumulator_len.is_power_of_two()
            || accumulator_len > padded_len
        {
            return Err(BlsDoryMatrixError::InvalidDimensions);
        }
        let rows = 1usize
            .checked_shl(nu as u32)
            .ok_or(BlsDoryMatrixError::InvalidDimensions)?;
        let columns = 1usize
            .checked_shl(sigma as u32)
            .ok_or(BlsDoryMatrixError::InvalidDimensions)?;
        let mut source = self.row_source(
            ExecutionArtifactMatrixTable::Accumulator,
            rows,
            columns,
            None,
        )?;
        commit_bls_dory_row_source_with_scratch(&mut source, nu, sigma, setup, scratch_directory)
            .map_err(map_execution_artifact_commit_error)
    }

    fn evaluate_accumulator(
        &mut self,
        statement: StructuredMatrixStatement,
        layer_weights: &[BlsDoryFr],
        row_weights: &[BlsDoryFr],
        column_weights: &[BlsDoryFr],
    ) -> Result<BlsDoryFr, BlsDoryMatrixError> {
        if layer_weights.len() != statement.layers
            || row_weights.len() != statement.rows
            || column_weights.len() != statement.cols
        {
            return Err(BlsDoryMatrixError::InvalidDimensions);
        }
        let mut values = vec![0; statement.cols];
        let mut evaluation = BlsDoryFr::zero();
        for (layer, layer_weight) in layer_weights.iter().copied().enumerate() {
            for (row, row_weight) in row_weights.iter().copied().enumerate() {
                let start = (layer * statement.rows + row) * statement.cols;
                self.read_values(
                    ExecutionArtifactMatrixTable::Accumulator,
                    start,
                    &mut values,
                )?;
                for (value, column_weight) in values.iter().zip(column_weights) {
                    evaluation = evaluation
                        + BlsDoryFr::from_i64(*value) * *column_weight * row_weight * layer_weight;
                }
            }
        }
        Ok(evaluation)
    }

    fn activation_partials(
        &mut self,
        statement: StructuredMatrixStatement,
        row_weights: &[BlsDoryFr],
    ) -> Result<Vec<BlsDoryFr>, BlsDoryMatrixError> {
        if row_weights.len() != statement.rows {
            return Err(BlsDoryMatrixError::InvalidDimensions);
        }
        let partial_len = statement
            .layers
            .checked_mul(statement.inner)
            .ok_or(BlsDoryMatrixError::InvalidDimensions)?;
        let mut partials = vec![BlsDoryFr::zero(); partial_len];
        let mut values = vec![0; statement.inner];
        for layer in 0..statement.layers {
            for (row, row_weight) in row_weights.iter().copied().enumerate() {
                let start = (layer * statement.rows + row) * statement.inner;
                self.read_values(ExecutionArtifactMatrixTable::Activation, start, &mut values)?;
                for (common, value) in values.iter().copied().enumerate() {
                    partials[layer * statement.inner + common] = partials
                        [layer * statement.inner + common]
                        + BlsDoryFr::from_i64(value) * row_weight;
                }
            }
        }
        Ok(partials)
    }
}

struct PaddedSignedRowSource<'a> {
    values: &'a [i64],
    rows: usize,
    columns: usize,
    word_scalar_count: usize,
    word_group_len: usize,
    dictionary: Vec<BlsDoryFr>,
    code_maximum: Option<u8>,
}

impl BlsDoryRowSource for PaddedSignedRowSource<'_> {
    type Error = ();

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

impl BlsDoryCompactRowSource for PaddedSignedRowSource<'_> {
    type Error = ();

    fn rows(&self) -> usize {
        self.rows
    }

    fn columns(&self) -> usize {
        self.columns
    }

    fn explicit_scalar_count(&self) -> usize {
        self.values.len()
    }

    fn word_scalar_count(&self) -> usize {
        self.word_scalar_count
    }

    fn word_group_len(&self) -> usize {
        self.word_group_len
    }

    fn signed_word_selectors(&self) -> u64 {
        1
    }

    fn dictionary(&self) -> &[BlsDoryFr] {
        &self.dictionary
    }

    fn read_word_row(
        &mut self,
        row_index: usize,
        output: &mut [u64],
    ) -> Result<usize, Self::Error> {
        let start = row_index * self.columns;
        for (column, word) in output.iter_mut().enumerate() {
            *word = self
                .values
                .get(start + column)
                .copied()
                .map(|value| u64::from_le_bytes(value.to_le_bytes()))
                .unwrap_or(0);
        }
        Ok(output.len())
    }

    fn read_code_row(&mut self, row_index: usize, output: &mut [u8]) -> Result<usize, Self::Error> {
        let maximum = self.code_maximum.ok_or(())?;
        let start = row_index * self.columns;
        for (column, code) in output.iter_mut().enumerate() {
            *code = match self.values.get(start + column).copied() {
                Some(value) => bounded_signed_code(value, maximum).ok_or(())?,
                None => 0,
            };
        }
        Ok(output.len())
    }
}

fn padded_signed_row_source<'a>(
    values: &'a [i64],
    rows: usize,
    columns: usize,
    code_maximum: Option<u8>,
) -> PaddedSignedRowSource<'a> {
    let use_codes = code_maximum
        .and_then(bounded_signed_dictionary)
        .filter(|_| values.len() > columns);
    if let Some(dictionary) = use_codes {
        return PaddedSignedRowSource {
            values,
            rows,
            columns,
            word_scalar_count: columns,
            word_group_len: columns,
            dictionary,
            code_maximum,
        };
    }
    PaddedSignedRowSource {
        values,
        rows,
        columns,
        word_scalar_count: values.len(),
        word_group_len: values.len(),
        dictionary: vec![BlsDoryFr::zero()],
        code_maximum: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn commit_signed_table(
    values: &[i64],
    padded_variables: usize,
    nu: usize,
    sigma: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: Option<&Path>,
) -> Result<BlsDoryCommittedPolynomial, BlsDoryMatrixError> {
    commit_signed_table_with_codes(
        values,
        None,
        padded_variables,
        nu,
        sigma,
        setup,
        scratch_directory,
    )
}

#[allow(clippy::too_many_arguments)]
fn commit_bounded_signed_table(
    values: &[i64],
    maximum: u64,
    padded_variables: usize,
    nu: usize,
    sigma: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: Option<&Path>,
) -> Result<BlsDoryCommittedPolynomial, BlsDoryMatrixError> {
    commit_signed_table_with_codes(
        values,
        u8::try_from(maximum).ok().filter(|maximum| *maximum <= 127),
        padded_variables,
        nu,
        sigma,
        setup,
        scratch_directory,
    )
}

#[allow(clippy::too_many_arguments)]
fn commit_signed_table_with_codes(
    values: &[i64],
    code_maximum: Option<u8>,
    padded_variables: usize,
    nu: usize,
    sigma: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: Option<&Path>,
) -> Result<BlsDoryCommittedPolynomial, BlsDoryMatrixError> {
    let padded_len = 1usize
        .checked_shl(padded_variables as u32)
        .ok_or(BlsDoryMatrixError::InvalidDimensions)?;
    if values.is_empty() || !values.len().is_power_of_two() || values.len() > padded_len {
        return Err(BlsDoryMatrixError::InvalidDimensions);
    }
    if let Some(scratch_directory) = scratch_directory {
        let rows = 1usize
            .checked_shl(nu as u32)
            .ok_or(BlsDoryMatrixError::InvalidDimensions)?;
        let columns = 1usize
            .checked_shl(sigma as u32)
            .ok_or(BlsDoryMatrixError::InvalidDimensions)?;
        let mut source = padded_signed_row_source(values, rows, columns, code_maximum);
        if values.len().is_multiple_of(columns) {
            return commit_bls_dory_compact_row_source_with_scratch(
                &mut source,
                nu,
                sigma,
                setup,
                scratch_directory,
            )
            .map_err(Into::into);
        }
        return commit_bls_dory_row_source_with_scratch(
            &mut source,
            nu,
            sigma,
            setup,
            scratch_directory,
        )
        .map_err(Into::into);
    }
    let mut padded = values
        .iter()
        .copied()
        .map(BlsDoryFr::from_i64)
        .collect::<Vec<_>>();
    padded.resize(padded_len, BlsDoryFr::zero());
    commit_bls_dory_polynomial(padded, nu, sigma, setup).map_err(Into::into)
}

fn pad_point(point: &[BlsDoryFr], variables: usize) -> Result<Vec<BlsDoryFr>, BlsDoryMatrixError> {
    if point.len() > variables {
        return Err(BlsDoryMatrixError::InvalidDimensions);
    }
    let mut padded = Vec::with_capacity(variables);
    padded.extend_from_slice(point);
    padded.resize(variables, BlsDoryFr::zero());
    Ok(padded)
}

fn activation_point(
    common: &[BlsDoryFr],
    row: &[BlsDoryFr],
    layer: &[BlsDoryFr],
) -> Vec<BlsDoryFr> {
    concatenate_points(&[common, row, layer])
}

fn weight_point(col: &[BlsDoryFr], common: &[BlsDoryFr], layer: &[BlsDoryFr]) -> Vec<BlsDoryFr> {
    concatenate_points(&[col, common, layer])
}

fn accumulator_point(col: &[BlsDoryFr], row: &[BlsDoryFr], layer: &[BlsDoryFr]) -> Vec<BlsDoryFr> {
    concatenate_points(&[col, row, layer])
}

fn concatenate_points(parts: &[&[BlsDoryFr]]) -> Vec<BlsDoryFr> {
    let mut point = Vec::with_capacity(parts.iter().map(|part| part.len()).sum());
    for part in parts {
        point.extend_from_slice(part);
    }
    point
}

fn matrix_opening_claims(
    commitments: [BlsDoryGt; 3],
    points: &[Vec<BlsDoryFr>],
    evaluations: [BlsDoryFr; 3],
) -> Vec<BlsDoryOpeningClaim> {
    commitments
        .into_iter()
        .zip(points)
        .zip(evaluations)
        .map(|((commitment, point), evaluation)| BlsDoryOpeningClaim {
            commitment,
            point: point.clone(),
            evaluation,
        })
        .collect()
}

fn product_round(
    selector: &[BlsDoryFr],
    left: &[BlsDoryFr],
    right: &[BlsDoryFr],
    degree: usize,
) -> Result<Vec<BlsDoryFr>, BlsDoryMatrixError> {
    if selector.len() != left.len()
        || left.len() != right.len()
        || selector.is_empty()
        || !selector.len().is_multiple_of(2)
    {
        return Err(BlsDoryMatrixError::InvalidDimensions);
    }
    Ok((0..=degree)
        .map(|sample| {
            let point = BlsDoryFr::from_u64(sample as u64);
            selector
                .chunks_exact(2)
                .zip(left.chunks_exact(2))
                .zip(right.chunks_exact(2))
                .fold(BlsDoryFr::zero(), |sum, ((selector, left), right)| {
                    sum + interpolate_pair(selector, point)
                        * interpolate_pair(left, point)
                        * interpolate_pair(right, point)
                })
        })
        .collect())
}

fn evaluate_samples(
    values: &[BlsDoryFr],
    point: BlsDoryFr,
) -> Result<BlsDoryFr, BlsDoryMatrixError> {
    if !matches!(values.len(), 3 | 4) {
        return Err(BlsDoryMatrixError::InvalidProofShape);
    }
    let mut result = BlsDoryFr::zero();
    for (index, value) in values.iter().copied().enumerate() {
        let mut numerator = BlsDoryFr::one();
        let mut denominator = BlsDoryFr::one();
        for other in 0..values.len() {
            if other == index {
                continue;
            }
            numerator = numerator * (point - BlsDoryFr::from_u64(other as u64));
            denominator = denominator * BlsDoryFr::from_i64(index as i64 - other as i64);
        }
        let inverse = denominator
            .inv()
            .ok_or(BlsDoryMatrixError::InvalidProofShape)?;
        result = result + value * numerator * inverse;
    }
    Ok(result)
}

fn equality_weights(point: &[BlsDoryFr]) -> Vec<BlsDoryFr> {
    let mut weights = vec![BlsDoryFr::one()];
    for challenge in point {
        let previous = weights;
        let half = previous.len();
        weights = vec![BlsDoryFr::zero(); half * 2];
        for (index, value) in previous.into_iter().enumerate() {
            weights[index] = value * (BlsDoryFr::one() - *challenge);
            weights[index + half] = value * challenge;
        }
    }
    weights
}

fn equality_evaluation(
    left: &[BlsDoryFr],
    right: &[BlsDoryFr],
) -> Result<BlsDoryFr, BlsDoryMatrixError> {
    if left.len() != right.len() {
        return Err(BlsDoryMatrixError::InvalidDimensions);
    }
    Ok(left
        .iter()
        .zip(right)
        .fold(BlsDoryFr::one(), |product, (left, right)| {
            product * (*left * *right + (BlsDoryFr::one() - *left) * (BlsDoryFr::one() - *right))
        }))
}

fn evaluate_accumulators(
    statement: StructuredMatrixStatement,
    accumulators: &[i64],
    layer_weights: &[BlsDoryFr],
    row_weights: &[BlsDoryFr],
    col_weights: &[BlsDoryFr],
) -> Result<BlsDoryFr, BlsDoryMatrixError> {
    let expected = statement
        .layers
        .checked_mul(statement.rows)
        .and_then(|count| count.checked_mul(statement.cols))
        .ok_or(BlsDoryMatrixError::InvalidDimensions)?;
    if accumulators.len() != expected
        || layer_weights.len() != statement.layers
        || row_weights.len() != statement.rows
        || col_weights.len() != statement.cols
    {
        return Err(BlsDoryMatrixError::InvalidDimensions);
    }
    let mut evaluation = BlsDoryFr::zero();
    for (layer, layer_weight) in layer_weights.iter().copied().enumerate() {
        for (row, row_weight) in row_weights.iter().copied().enumerate() {
            for (column, column_weight) in col_weights.iter().copied().enumerate() {
                let index = (layer * statement.rows + row) * statement.cols + column;
                evaluation = evaluation
                    + BlsDoryFr::from_i64(accumulators[index])
                        * column_weight
                        * row_weight
                        * layer_weight;
            }
        }
    }
    Ok(evaluation)
}

fn fold(table: &[BlsDoryFr], challenge: BlsDoryFr) -> Result<Vec<BlsDoryFr>, BlsDoryMatrixError> {
    if table.is_empty() || !table.len().is_multiple_of(2) {
        return Err(BlsDoryMatrixError::InvalidDimensions);
    }
    Ok(table
        .chunks_exact(2)
        .map(|pair| interpolate_pair(pair, challenge))
        .collect())
}

fn interpolate_pair(pair: &[BlsDoryFr], point: BlsDoryFr) -> BlsDoryFr {
    pair[0] + point * (pair[1] - pair[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dory_bls12_381_prototype::deterministic_bls_dory_setup;

    static SCRATCH_NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

    struct ScratchDirectory(std::path::PathBuf);

    impl ScratchDirectory {
        fn create() -> Self {
            let nonce = SCRATCH_NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "cmfd-dory-matrix-source-test-{}-{nonce}",
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

    fn fixture() -> (StructuredMatrixStatement, Vec<i64>, Vec<i64>, Vec<i64>) {
        let statement = StructuredMatrixStatement {
            layers: 2,
            rows: 2,
            inner: 2,
            cols: 2,
            max_abs_activation: 10,
            max_abs_weight: 10,
            max_abs_accumulator: 100,
        };
        let activations = vec![1, 2, 3, 4, -1, 2, 5, -2];
        let weights = vec![2, 1, -1, 3, 4, -2, 1, 5];
        let accumulators = vec![0, 7, 2, 15, -2, 12, 18, -20];
        (statement, activations, weights, accumulators)
    }

    fn computed_accumulators(
        statement: StructuredMatrixStatement,
        activations: &[i64],
        weights: &[i64],
    ) -> Vec<i64> {
        let mut accumulators =
            Vec::with_capacity(statement.layers * statement.rows * statement.cols);
        for layer in 0..statement.layers {
            for row in 0..statement.rows {
                for col in 0..statement.cols {
                    let mut sum = 0_i64;
                    for common in 0..statement.inner {
                        let activation =
                            activations[(layer * statement.rows + row) * statement.inner + common];
                        let weight =
                            weights[(layer * statement.inner + common) * statement.cols + col];
                        sum += activation * weight;
                    }
                    accumulators.push(sum);
                }
            }
        }
        accumulators
    }

    fn computed_layer_accumulators(
        rows: usize,
        inner: usize,
        cols: usize,
        activations: &[i64],
        weights: &[i64],
    ) -> Vec<i64> {
        let mut accumulators = Vec::with_capacity(rows * cols);
        for row in 0..rows {
            for col in 0..cols {
                let mut sum = 0_i64;
                for common in 0..inner {
                    sum += activations[row * inner + common] * weights[common * cols + col];
                }
                accumulators.push(sum);
            }
        }
        accumulators
    }

    fn transition_activations(
        statement: StructuredTransitionStatement,
        mask: &StructuredMaskPolynomial,
        layer: usize,
        accumulators: &[i64],
    ) -> Vec<i64> {
        let cells = statement.rows * statement.cols;
        accumulators
            .iter()
            .copied()
            .enumerate()
            .map(|(cell, accumulator)| {
                let index = layer * cells + cell;
                let mask_value = mask
                    .value_at_boolean_index_prevalidated(statement, index)
                    .unwrap();
                derive_transition_regular_row_from_mask(statement, index, accumulator, mask_value)
                    .unwrap()
                    .activation
            })
            .collect()
    }

    #[test]
    fn exact_matrix_sumcheck_is_authenticated_by_three_commitments() {
        let (statement, activations, weights, accumulators) = fixture();
        let setup = deterministic_bls_dory_setup(3).unwrap();
        let proof = prove_bls_dory_matrix(
            b"block-binding",
            statement,
            &activations,
            &weights,
            &accumulators,
            &setup,
        )
        .unwrap();
        verify_bls_dory_matrix(b"block-binding", statement, &proof, &setup).unwrap();
        assert_eq!(proof.padded_variables, 3);
        assert_eq!(proof.rounds.len(), 2);
        assert_eq!(proof.rounds[0].len(), 3);
        assert_eq!(proof.rounds[1].len(), 4);
        assert_eq!(proof.opening_proof.len(), 9_439);

        let encoded = proof.encode(statement).unwrap();
        assert_eq!(encoded.len(), 11_539);
        let decoded = BlsDoryMatrixProof::decode(&encoded, statement).unwrap();
        assert_eq!(decoded, proof);
        verify_bls_dory_matrix(b"block-binding", statement, &decoded, &setup).unwrap();
    }

    #[test]
    fn precommitted_weight_preserves_exact_proof_and_cleans_artifacts() {
        let (statement, activations, weights, accumulators) = fixture();
        let variables = matrix_variables(statement).unwrap();
        let nu = variables / 2;
        let sigma = variables - nu;
        let columns = 1usize << sigma;
        let mut activation_source = padded_signed_row_source(
            &activations,
            1usize << nu,
            columns,
            Some(u8::try_from(statement.max_abs_activation).unwrap()),
        );
        assert_eq!(activation_source.word_scalar_count, columns);
        assert_eq!(activation_source.word_group_len, columns);
        assert_eq!(activation_source.dictionary.len(), 21);
        let mut activation_codes = vec![0; columns];
        activation_source
            .read_code_row(1, &mut activation_codes)
            .unwrap();
        assert_eq!(activation_codes, [1, 12, 15, 2]);
        let setup = deterministic_bls_dory_setup(variables).unwrap();
        let scratch = ScratchDirectory::create();
        let dense = prove_bls_dory_matrix_deferred_at_variables(
            b"precommitted-weight",
            statement,
            &activations,
            &weights,
            &accumulators,
            variables,
            &setup,
        )
        .unwrap();
        let ordinary = prove_bls_dory_matrix_deferred_at_variables_with_scratch(
            b"precommitted-weight",
            statement,
            &activations,
            &weights,
            &accumulators,
            variables,
            &setup,
            &scratch.0,
        )
        .unwrap();
        assert_eq!(ordinary.proof, dense.proof);
        assert_eq!(ordinary.openings.claims(), dense.openings.claims());
        let aggregate_binding =
            opening_binding(b"precommitted-weight", &ordinary.proof.transcript_digest);
        let aggregate_layout = BlsDoryAggregateLayout::new(nu, sigma).unwrap();
        let dense_opening = prove_bls_dory_deferred_opening_sets(
            &aggregate_binding,
            aggregate_layout,
            &[&dense.openings],
            &setup,
        )
        .unwrap();
        let compact_opening = prove_bls_dory_deferred_opening_sets_with_scratch(
            &aggregate_binding,
            aggregate_layout,
            &[&ordinary.openings],
            &setup,
            &scratch.0,
        )
        .unwrap();
        assert_eq!(compact_opening, dense_opening);
        let weight = commit_bounded_signed_table(
            &weights,
            statement.max_abs_weight,
            variables,
            nu,
            sigma,
            &setup,
            Some(&scratch.0),
        )
        .unwrap();
        assert_eq!(
            weight
                .coefficient_artifact_path()
                .unwrap()
                .metadata()
                .unwrap()
                .len(),
            836
        );
        let streamed = prove_bls_dory_matrix_deferred_with_precommitted_weight_and_scratch(
            b"precommitted-weight",
            statement,
            &activations,
            &weight,
            &accumulators,
            variables,
            &setup,
            &scratch.0,
        )
        .unwrap();
        assert_eq!(streamed.proof, ordinary.proof);
        assert_eq!(streamed.openings.claims(), ordinary.openings.claims());
        drop(streamed);
        drop(weight);

        let mut out_of_range_weights = weights;
        out_of_range_weights[0] = statement.max_abs_weight as i64 + 1;
        let out_of_range_accumulators =
            computed_accumulators(statement, &activations, &out_of_range_weights);
        let out_of_range_weight = commit_signed_table(
            &out_of_range_weights,
            variables,
            nu,
            sigma,
            &setup,
            Some(&scratch.0),
        )
        .unwrap();
        assert!(matches!(
            prove_bls_dory_matrix_deferred_with_precommitted_weight_and_scratch(
                b"precommitted-weight",
                statement,
                &activations,
                &out_of_range_weight,
                &out_of_range_accumulators,
                variables,
                &setup,
                &scratch.0,
            ),
            Err(BlsDoryMatrixError::Structured(
                StructuredSumcheckError::ValueOutOfRange
            ))
        ));
        drop(out_of_range_weight);
        drop(dense);
        drop(ordinary);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn execution_artifact_banks_preserve_matrix_proof_bytes_and_cleanup() {
        use crate::dory_bls12_381_execution_artifact::BlsDoryExecutionAccumulatorArtifactWriter;

        let statement = StructuredMatrixStatement {
            layers: 2,
            rows: 2,
            inner: 2,
            cols: 2,
            max_abs_activation: 125,
            max_abs_weight: 10,
            max_abs_accumulator: 10_000,
        };
        let initialization_statement = StructuredTransitionStatement {
            layers: 1,
            rows: 2,
            cols: 2,
            max_abs_accumulator: 125,
            max_mask: 5_000,
        };
        let transition_statement = StructuredTransitionStatement {
            layers: 2,
            rows: 2,
            cols: 2,
            max_abs_accumulator: statement.max_abs_accumulator,
            max_mask: 5_000,
        };
        let challenge = [0x5a; 32];
        let initialization_mask =
            StructuredMaskPolynomial::from_virtual_challenge(&challenge, 2, 2).unwrap();
        let bank_masks = [
            StructuredMaskPolynomial::from_challenge_at_layer_offset(&challenge, 0, 2, 2, 2)
                .unwrap(),
            StructuredMaskPolynomial::from_challenge_at_layer_offset(&challenge, 2, 2, 2, 2)
                .unwrap(),
        ];
        let layer_weights = [
            vec![1, 2, -1, 1],
            vec![2, -1, 1, 2],
            vec![1, 0, 2, -2],
            vec![-1, 2, 2, 1],
        ];
        let initialization_accumulators = vec![3, -4, 5, 1];
        let mut activation = transition_activations(
            initialization_statement,
            &initialization_mask,
            0,
            &initialization_accumulators,
        );
        let mut bank_activations = [Vec::new(), Vec::new()];
        let mut bank_weights = [Vec::new(), Vec::new()];
        let mut bank_accumulators = [Vec::new(), Vec::new()];
        for (global_layer, weights) in layer_weights.iter().enumerate() {
            let bank = global_layer / statement.layers;
            let layer = global_layer % statement.layers;
            bank_activations[bank].extend_from_slice(&activation);
            bank_weights[bank].extend_from_slice(weights);
            let accumulators = computed_layer_accumulators(2, 2, 2, &activation, weights);
            bank_accumulators[bank].extend_from_slice(&accumulators);
            activation = transition_activations(
                transition_statement,
                &bank_masks[bank],
                layer,
                &accumulators,
            );
        }

        let variables = matrix_variables(statement).unwrap();
        let nu = variables / 2;
        let sigma = variables - nu;
        let setup = deterministic_bls_dory_setup(variables).unwrap();
        let scratch = ScratchDirectory::create();
        let context = BlsDoryExecutionAccumulatorArtifactContext::for_test(
            [[0x11; 32], [0x22; 32], setup.identity(), challenge],
            statement.rows,
            statement.cols,
            2,
            statement.layers,
            2,
        )
        .unwrap();
        let mut writer =
            BlsDoryExecutionAccumulatorArtifactWriter::create_new(&scratch.0, context).unwrap();
        for chunk in initialization_accumulators.chunks_exact(2) {
            writer
                .write_column_chunk(
                    BlsDoryExecutionAccumulatorColumn::Initialization,
                    &chunk
                        .iter()
                        .copied()
                        .map(i32::try_from)
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap(),
                )
                .unwrap();
        }
        let cells = statement.rows * statement.cols;
        for (bank, accumulators) in bank_accumulators.iter().enumerate() {
            for layer in 0..statement.layers {
                let values = &accumulators[layer * cells..(layer + 1) * cells];
                for chunk in values.chunks_exact(2) {
                    writer
                        .write_column_chunk(
                            BlsDoryExecutionAccumulatorColumn::BankLayer { bank, layer },
                            &chunk
                                .iter()
                                .copied()
                                .map(i32::try_from)
                                .collect::<Result<Vec<_>, _>>()
                                .unwrap(),
                        )
                        .unwrap();
                }
            }
        }
        let mut artifact = writer.finish().unwrap();

        let weights = bank_weights
            .iter()
            .map(|values| {
                commit_bounded_signed_table(
                    values,
                    statement.max_abs_weight,
                    variables,
                    nu,
                    sigma,
                    &setup,
                    Some(&scratch.0),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let mut dense_proofs = Vec::new();
        let mut artifact_proofs = Vec::new();
        for bank in 0..2 {
            let binding = format!("artifact-matrix-bank-{bank}");
            let dense = prove_bls_dory_matrix_deferred_with_precommitted_weight_and_scratch(
                binding.as_bytes(),
                statement,
                &bank_activations[bank],
                &weights[bank],
                &bank_accumulators[bank],
                variables,
                &setup,
                &scratch.0,
            )
            .unwrap();
            let (prior_statement, prior_mask) = if bank == 0 {
                (initialization_statement, &initialization_mask)
            } else {
                (transition_statement, &bank_masks[bank - 1])
            };
            let streamed = prove_bls_dory_matrix_deferred_with_precommitted_weight_from_execution_artifact_and_scratch(
                binding.as_bytes(),
                statement,
                &weights[bank],
                &mut artifact,
                context,
                BlsDoryExecutionArtifactMatrixInput {
                    bank,
                    prior_statement,
                    prior_mask,
                    current_statement: transition_statement,
                    current_mask: &bank_masks[bank],
                },
                variables,
                &setup,
                &scratch.0,
            )
            .unwrap();
            assert_eq!(streamed.proof, dense.proof);
            assert_eq!(
                streamed.proof.encode_deferred(statement).unwrap(),
                dense.proof.encode_deferred(statement).unwrap()
            );
            assert_eq!(streamed.openings.claims(), dense.openings.claims());
            dense_proofs.push(dense);
            artifact_proofs.push(streamed);
        }

        let wrong_current_mask =
            StructuredMaskPolynomial::from_challenge_at_layer_offset(&[0x6b; 32], 0, 2, 2, 2)
                .unwrap();
        assert!(matches!(
            prove_bls_dory_matrix_deferred_with_precommitted_weight_from_execution_artifact_and_scratch(
                b"wrong-challenge-mask",
                statement,
                &weights[0],
                &mut artifact,
                context,
                BlsDoryExecutionArtifactMatrixInput {
                    bank: 0,
                    prior_statement: initialization_statement,
                    prior_mask: &initialization_mask,
                    current_statement: transition_statement,
                    current_mask: &wrong_current_mask,
                },
                variables,
                &setup,
                &scratch.0,
            ),
            Err(BlsDoryMatrixError::ExecutionArtifact)
        ));

        let wrong_context = BlsDoryExecutionAccumulatorArtifactContext::for_test(
            [[0x11; 32], [0x22; 32], setup.identity(), [0x55; 32]],
            statement.rows,
            statement.cols,
            2,
            statement.layers,
            2,
        )
        .unwrap();
        assert!(matches!(
            prove_bls_dory_matrix_deferred_with_precommitted_weight_from_execution_artifact_and_scratch(
                b"wrong-context",
                statement,
                &weights[0],
                &mut artifact,
                wrong_context,
                BlsDoryExecutionArtifactMatrixInput {
                    bank: 0,
                    prior_statement: initialization_statement,
                    prior_mask: &initialization_mask,
                    current_statement: transition_statement,
                    current_mask: &bank_masks[0],
                },
                variables,
                &setup,
                &scratch.0,
            ),
            Err(BlsDoryMatrixError::ExecutionArtifact)
        ));

        drop(artifact_proofs);
        drop(dense_proofs);
        drop(weights);
        drop(artifact);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn high_zero_padding_preserves_unequal_table_geometries() {
        let statement = StructuredMatrixStatement {
            layers: 2,
            rows: 2,
            inner: 4,
            cols: 8,
            max_abs_activation: 20,
            max_abs_weight: 20,
            max_abs_accumulator: 2_000,
        };
        let activations = (0..statement.layers * statement.rows * statement.inner)
            .map(|index| index as i64 % 7 - 3)
            .collect::<Vec<_>>();
        let weights = (0..statement.layers * statement.inner * statement.cols)
            .map(|index| index as i64 % 9 - 4)
            .collect::<Vec<_>>();
        let accumulators = computed_accumulators(statement, &activations, &weights);
        let setup = deterministic_bls_dory_setup(6).unwrap();
        let proof = prove_bls_dory_matrix(
            b"padding",
            statement,
            &activations,
            &weights,
            &accumulators,
            &setup,
        )
        .unwrap();
        assert_eq!(proof.padded_variables, 6);
        verify_bls_dory_matrix(b"padding", statement, &proof, &setup).unwrap();
    }

    #[test]
    fn binding_statement_commitments_rounds_terminals_and_opening_are_bound() {
        let (statement, activations, weights, accumulators) = fixture();
        let setup = deterministic_bls_dory_setup(3).unwrap();
        let proof = prove_bls_dory_matrix(
            b"binding",
            statement,
            &activations,
            &weights,
            &accumulators,
            &setup,
        )
        .unwrap();
        assert!(verify_bls_dory_matrix(b"other", statement, &proof, &setup).is_err());

        let mut changed_statement = statement;
        changed_statement.max_abs_accumulator += 1;
        assert!(verify_bls_dory_matrix(b"binding", changed_statement, &proof, &setup).is_err());

        for role in 0..3 {
            let mut commitment = proof.clone();
            match role {
                0 => commitment.activation_commitment = BlsDoryGt::identity(),
                1 => commitment.weight_commitment = BlsDoryGt::identity(),
                _ => commitment.accumulator_commitment = BlsDoryGt::identity(),
            }
            assert!(
                verify_bls_dory_matrix(b"binding", statement, &commitment, &setup).is_err(),
                "commitment role {role} was not bound"
            );
        }

        let mut accumulator = proof.clone();
        accumulator.accumulator_evaluation = accumulator.accumulator_evaluation + BlsDoryFr::one();
        assert!(verify_bls_dory_matrix(b"binding", statement, &accumulator, &setup).is_err());

        for round in 0..proof.rounds.len() {
            for evaluation in 0..proof.rounds[round].len() {
                let mut changed = proof.clone();
                changed.rounds[round][evaluation] =
                    changed.rounds[round][evaluation] + BlsDoryFr::one();
                assert!(
                    verify_bls_dory_matrix(b"binding", statement, &changed, &setup).is_err(),
                    "round {round} evaluation {evaluation} was not bound"
                );
            }
        }

        for terminal in 0..2 {
            let mut changed = proof.clone();
            if terminal == 0 {
                changed.activation_evaluation = changed.activation_evaluation + BlsDoryFr::one();
            } else {
                changed.weight_evaluation = changed.weight_evaluation + BlsDoryFr::one();
            }
            assert!(verify_bls_dory_matrix(b"binding", statement, &changed, &setup).is_err());
        }

        let mut digest = proof.clone();
        digest.transcript_digest[0] ^= 1;
        assert!(verify_bls_dory_matrix(b"binding", statement, &digest, &setup).is_err());

        let mut opening = proof.clone();
        let middle = opening.opening_proof.len() / 2;
        opening.opening_proof[middle] ^= 1;
        assert!(verify_bls_dory_matrix(b"binding", statement, &opening, &setup).is_err());

        let mut invalid_accumulators = accumulators;
        invalid_accumulators[0] += 1;
        assert!(
            prove_bls_dory_matrix(
                b"binding",
                statement,
                &activations,
                &weights,
                &invalid_accumulators,
                &setup,
            )
            .is_err()
        );
    }

    #[test]
    fn production_geometry_and_gate_remain_explicit() {
        let statement = production_matrix_statement();
        assert_eq!(PRODUCTION_BLS_DORY_MATRIX_VARIABLES, 31);
        assert_eq!(matrix_variables(statement).unwrap(), 31);
        assert_eq!(statement.sumcheck_error_numerator().unwrap(), 45);
        assert_eq!(projected_production_matrix_opening_bytes().unwrap(), 66_559);
        assert_eq!(projected_production_matrix_proof_bytes().unwrap(), 70_483);
        assert!(projected_production_matrix_proof_bytes().unwrap() < 262_128);
        assert_eq!(
            require_bls_dory_matrix_production_ready(),
            Err(BlsDoryMatrixError::NotProductionReady)
        );
        assert_eq!(BLS_DORY_MATRIX_PRODUCTION_BLOCKERS.len(), 4);
    }

    #[test]
    fn outer_parser_rejects_shape_mutations_before_curve_decoding() {
        let (statement, activations, weights, accumulators) = fixture();
        let setup = deterministic_bls_dory_setup(3).unwrap();
        let proof = prove_bls_dory_matrix(
            b"parser",
            statement,
            &activations,
            &weights,
            &accumulators,
            &setup,
        )
        .unwrap();
        let encoded = proof.encode(statement).unwrap();

        for range in [10..12, 12..14, 14..16] {
            let mut changed = encoded.clone();
            changed[range].copy_from_slice(&u16::MAX.to_le_bytes());
            assert_eq!(
                BlsDoryMatrixProof::decode(&changed, statement),
                Err(BlsDoryMatrixError::InvalidProofShape)
            );
        }

        let mut opening = encoded.clone();
        opening[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            BlsDoryMatrixProof::decode(&opening, statement),
            Err(BlsDoryMatrixError::InvalidProofShape)
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            BlsDoryMatrixProof::decode(&trailing, statement),
            Err(BlsDoryMatrixError::InvalidProofShape)
        );
        assert!(BlsDoryMatrixProof::decode(&encoded[..encoded.len() - 1], statement).is_err());
        assert_eq!(
            verify_bls_dory_matrix(
                &vec![0; MAX_MATRIX_BINDING_BYTES + 1],
                statement,
                &proof,
                &setup
            ),
            Err(BlsDoryMatrixError::PublicBindingTooLarge)
        );
    }
}
