//! BLS12-381 bank-batched matrix sumcheck authenticated by Dory.
//!
//! Activation, model-weight, and accumulator tables retain distinct
//! commitments. Smaller tables are zero-padded only in high variables so all
//! three use one Dory layout. The exact degree-two common rounds and
//! degree-three layer rounds reduce the matrix relation to three authenticated
//! multilinear openings.

use std::io::Cursor;

use dory_pcs::primitives::{
    DoryDeserialize, DorySerialize,
    arithmetic::{Field, Group},
    serialization::{Compress, Validate},
    transcript::Transcript,
};
use thiserror::Error;

use crate::{
    StructuredMatrixStatement, StructuredSumcheckError,
    dory_bls12_381_aggregate::{
        BlsDoryAggregateError, BlsDoryDeferredOpeningSet, BlsDoryOpeningClaim,
        MAX_BLS_DORY_AGGREGATE_BYTES, commit_bls_dory_polynomial,
        projected_bls_dory_aggregate_bytes, prove_bls_dory_deferred_opening_sets,
        verify_bls_dory_openings,
    },
    dory_bls12_381_prototype::{
        BlsDoryFr, BlsDoryGt, BlsDoryTranscript, DeterministicBlsDorySetup,
    },
    structured_sumcheck::validate_tables,
};

/// Version of the scalar-field matrix transcript.
pub const BLS_DORY_MATRIX_VERSION: u16 = 1;
/// Production weights contain 128 * 4096 * 4096 = 2^31 elements.
pub const PRODUCTION_BLS_DORY_MATRIX_VARIABLES: usize = 31;
/// This checkpoint is not accepted by consensus.
pub const BLS_DORY_MATRIX_PRODUCTION_READY: bool = false;
/// Remaining gates on the scalar matrix path.
pub const BLS_DORY_MATRIX_PRODUCTION_BLOCKERS: [&str; 5] = [
    "the n=31 activation, weight, and accumulator polynomials are not streamed by the in-memory prover",
    "the model-weight commitment is not yet derived from the pinned production ModelPcsIdentity",
    "the activation and accumulator commitments are not yet linked to wiring and transition roles",
    "the complete union-bound and Dory knowledge-soundness analysis is not independently reviewed",
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
    let (claims, opening_proof) =
        prove_bls_dory_deferred_opening_sets(&opening_binding, &[&prepared.openings], setup)?;
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
    if binding.len() > MAX_MATRIX_BINDING_BYTES {
        return Err(BlsDoryMatrixError::PublicBindingTooLarge);
    }
    validate_tables(statement, activations, weights, accumulators)?;
    validate_target_variables(matrix_variables(statement)?, padded_variables)?;
    if padded_variables > setup.max_log_n() {
        return Err(BlsDoryMatrixError::InvalidDimensions);
    }
    let activation_values = signed_values(activations);
    let weight_values = signed_values(weights);
    let accumulator_values = signed_values(accumulators);
    let nu = padded_variables / 2;
    let sigma = padded_variables - nu;
    let activation_polynomial = commit_bls_dory_polynomial(
        pad_coefficients(&activation_values, padded_variables)?,
        nu,
        sigma,
        setup,
    )?;
    let weight_polynomial = commit_bls_dory_polynomial(
        pad_coefficients(&weight_values, padded_variables)?,
        nu,
        sigma,
        setup,
    )?;
    let accumulator_polynomial = commit_bls_dory_polynomial(
        pad_coefficients(&accumulator_values, padded_variables)?,
        nu,
        sigma,
        setup,
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
    let accumulator_evaluation = evaluate_mle(&accumulator_values, &accumulator_point)?;
    transcript.append_field(b"accumulator-evaluation", &accumulator_evaluation);

    let layer_weights = equality_weights(&layer_point);
    let row_weights = equality_weights(&row_point);
    let col_weights = equality_weights(&col_point);
    let partial_len = statement
        .layers
        .checked_mul(statement.inner)
        .ok_or(BlsDoryMatrixError::InvalidDimensions)?;
    let mut layer_selector = Vec::with_capacity(partial_len);
    let mut activation_partial = Vec::with_capacity(partial_len);
    let mut weight_partial = Vec::with_capacity(partial_len);
    for (layer, layer_weight) in layer_weights.iter().copied().enumerate() {
        for common in 0..statement.inner {
            layer_selector.push(layer_weight);
            let mut activation = BlsDoryFr::zero();
            for (row, row_weight) in row_weights.iter().copied().enumerate() {
                let index = (layer * statement.rows + row) * statement.inner + common;
                activation = activation + activation_values[index] * row_weight;
            }
            activation_partial.push(activation);

            let mut weight = BlsDoryFr::zero();
            for (col, col_weight) in col_weights.iter().copied().enumerate() {
                let index = (layer * statement.inner + common) * statement.cols + col;
                weight = weight + weight_values[index] * col_weight;
            }
            weight_partial.push(weight);
        }
    }

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
    verify_bls_dory_openings(&binding, &claims, &proof.opening_proof, setup)?;
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

fn signed_values(values: &[i64]) -> Vec<BlsDoryFr> {
    values.iter().copied().map(BlsDoryFr::from_i64).collect()
}

fn pad_coefficients(
    values: &[BlsDoryFr],
    variables: usize,
) -> Result<Vec<BlsDoryFr>, BlsDoryMatrixError> {
    let padded_len = 1usize
        .checked_shl(variables as u32)
        .ok_or(BlsDoryMatrixError::InvalidDimensions)?;
    if values.is_empty() || !values.len().is_power_of_two() || values.len() > padded_len {
        return Err(BlsDoryMatrixError::InvalidDimensions);
    }
    let mut padded = Vec::with_capacity(padded_len);
    padded.extend_from_slice(values);
    padded.resize(padded_len, BlsDoryFr::zero());
    Ok(padded)
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

fn evaluate_mle(
    values: &[BlsDoryFr],
    point: &[BlsDoryFr],
) -> Result<BlsDoryFr, BlsDoryMatrixError> {
    let expected = 1usize
        .checked_shl(point.len() as u32)
        .ok_or(BlsDoryMatrixError::InvalidDimensions)?;
    if values.len() != expected {
        return Err(BlsDoryMatrixError::InvalidDimensions);
    }
    let mut table = values.to_vec();
    for challenge in point {
        table = fold(&table, *challenge)?;
    }
    table
        .first()
        .copied()
        .ok_or(BlsDoryMatrixError::InvalidDimensions)
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
        assert_eq!(BLS_DORY_MATRIX_PRODUCTION_BLOCKERS.len(), 5);
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
